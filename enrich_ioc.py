#!/usr/bin/env python3
"""
enrich_ioc.py — enrichissement d'IOC à partir de sources publiques.

Principe de conception : TOUT ce qui sort du périmètre est explicite.
Un IOC interne (RFC1918, loopback, suffixe DNS interne) n'est JAMAIS envoyé
à un tiers. Le mode --dry-run montre exactement ce qui partirait, sans
émettre une seule requête.

Sources utilisées :
  IP       -> AbuseIPDB (clé)      + GreyNoise Community (clé)
  Domaine  -> URLhaus host (abuse.ch)
  Hash     -> MalwareBazaar (abuse.ch)

Clés via variables d'environnement :
  ABUSEIPDB_KEY, GREYNOISE_KEY, ABUSECH_KEY
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("Module manquant : pip install requests")


# ---------------------------------------------------------------------------
# 1. Périmètre — ce qui ne doit jamais sortir
# ---------------------------------------------------------------------------

# À adapter à ton environnement. Tout IOC correspondant reste local.
SUFFIXES_INTERNES = (
    ".corp.local",
    ".ad.<ENTREPRISE>.fr",
    ".<ENTREPRISE>.intra",
)

# Plages publiques t'appartenant (NAT sortant, DMZ, VPN...).
# Les interroger revient à publier ton plan d'adressage.
PLAGES_PROPRIETAIRES = (
    "<X.X.X.X/24>",
)


def est_interne(valeur, type_ioc):
    """Retourne (True, raison) si l'IOC ne doit pas quitter le périmètre."""
    if type_ioc == "ip":
        try:
            ip = ipaddress.ip_address(valeur)
        except ValueError:
            return True, "IP invalide"
        if ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return True, "adresse non routable"
        if ip.is_private:
            return True, "adresse privée (RFC 1918)"
        for plage in PLAGES_PROPRIETAIRES:
            if plage.startswith("<"):
                continue  # placeholder non renseigné
            if ip in ipaddress.ip_network(plage, strict=False):
                return True, f"plage propriétaire {plage}"
        return False, None

    if type_ioc in ("domaine", "url"):
        cible = valeur.lower()
        for suffixe in SUFFIXES_INTERNES:
            if suffixe.startswith(".<") or "<" in suffixe:
                continue  # placeholder non renseigné
            if suffixe in cible:
                return True, f"suffixe DNS interne {suffixe}"
        return False, None

    # Un hash ne révèle pas d'infrastructure, mais révèle qu'un fichier
    # t'intéresse. Acceptable pour un hash connu, à proscrire pour un
    # document interne dont le hash est unique au monde.
    return False, None


# ---------------------------------------------------------------------------
# 2. Typage de l'IOC
# ---------------------------------------------------------------------------

RE_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
RE_DOMAINE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)


def detecter_type(valeur):
    valeur = valeur.strip()
    if not valeur:
        return None
    if valeur.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(valeur)
        return "ip"
    except ValueError:
        pass
    if RE_HASH.match(valeur):
        return "hash"
    if RE_DOMAINE.match(valeur):
        return "domaine"
    return None


# ---------------------------------------------------------------------------
# 3. Limitation de débit — les quotas gratuits sont vite épuisés
# ---------------------------------------------------------------------------

class Limiteur:
    """Impose un intervalle minimum entre deux appels d'une même source."""

    def __init__(self):
        self.dernier = {}
        self.appels = {}

    def attendre(self, source, intervalle):
        precedent = self.dernier.get(source)
        if precedent is not None:
            reste = intervalle - (time.monotonic() - precedent)
            if reste > 0:
                time.sleep(reste)
        self.dernier[source] = time.monotonic()
        self.appels[source] = self.appels.get(source, 0) + 1


LIMITEUR = Limiteur()
TIMEOUT = 10


def appeler(source, intervalle, methode, url, codes_valides=(200,), **kwargs):
    """Appel HTTP avec limitation de débit et gestion d'erreur uniforme."""
    LIMITEUR.attendre(source, intervalle)
    try:
        r = requests.request(methode, url, timeout=TIMEOUT, **kwargs)
    except requests.RequestException as e:
        return {"erreur": f"{type(e).__name__}"}
    if r.status_code == 429:
        return {"erreur": "quota dépassé (429)"}
    if r.status_code in (401, 403):
        return {"erreur": f"authentification refusée ({r.status_code})"}
    if r.status_code not in codes_valides:
        return {"erreur": f"HTTP {r.status_code}"}
    try:
        return r.json()
    except ValueError:
        return {"erreur": "réponse non JSON"}


# ---------------------------------------------------------------------------
# 4. Connecteurs
# ---------------------------------------------------------------------------

def abuseipdb(ip):
    cle = os.getenv("ABUSEIPDB_KEY")
    if not cle:
        return {"erreur": "ABUSEIPDB_KEY non définie"}
    data = appeler(
        "abuseipdb", 1.0, "GET",
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": cle, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
    )
    if "erreur" in data:
        return data
    d = data.get("data", {})
    return {
        "score_abus": d.get("abuseConfidenceScore"),
        "signalements": d.get("totalReports"),
        "pays": d.get("countryCode"),
        "fai": d.get("isp"),
        "usage": d.get("usageType"),
    }


def greynoise(ip):
    cle = os.getenv("GREYNOISE_KEY")
    entetes = {"Accept": "application/json"}
    if cle:
        entetes["key"] = cle
    data = appeler(
        "greynoise", 1.0, "GET",
        f"https://api.greynoise.io/v3/community/{ip}",
        codes_valides=(200, 404),
        headers=entetes,
    )
    if "erreur" in data:
        return data
    if not data.get("noise") and not data.get("riot"):
        return {"classification": "non observée"}
    return {
        "classification": data.get("classification"),
        "acteur": data.get("name"),
        "bruit_de_fond": data.get("noise"),
        "legitime": data.get("riot"),
    }


def urlhaus_host(hote):
    """Historique d'URL malveillantes hébergées sur ce domaine ou cette IP."""
    entetes = {}
    cle = os.getenv("ABUSECH_KEY")
    if cle:
        entetes["Auth-Key"] = cle
    data = appeler(
        "abusech", 2.0, "POST",
        "https://urlhaus-api.abuse.ch/v1/host/",
        headers=entetes, data={"host": hote},
    )
    if "erreur" in data:
        return data
    if data.get("query_status") != "ok":
        return {"verdict": data.get("query_status")}
    return {
        "urls_malveillantes": data.get("url_count"),
        "premiere_vue": data.get("firstseen"),
        "liste_noire": data.get("blacklists"),
    }


def malwarebazaar(hash_):
    entetes = {}
    cle = os.getenv("ABUSECH_KEY")
    if cle:
        entetes["Auth-Key"] = cle
    data = appeler(
        "abusech", 2.0, "POST",
        "https://mb-api.abuse.ch/api/v1/",
        headers=entetes, data={"query": "get_info", "hash": hash_},
    )
    if "erreur" in data:
        return data
    if data.get("query_status") != "ok":
        return {"verdict": data.get("query_status")}
    ech = (data.get("data") or [{}])[0]
    return {
        "nom_fichier": ech.get("file_name"),
        "type": ech.get("file_type"),
        "famille": ech.get("signature"),
        "premiere_vue": ech.get("first_seen"),
        "tags": ech.get("tags"),
    }


ROUTAGE = {
    "ip": [("abuseipdb", abuseipdb), ("greynoise", greynoise), ("urlhaus", urlhaus_host)],
    "domaine": [("urlhaus", urlhaus_host)],
    "hash": [("malwarebazaar", malwarebazaar)],
}


# ---------------------------------------------------------------------------
# 5. Orchestration
# ---------------------------------------------------------------------------

def enrichir(valeur, dry_run=False):
    type_ioc = detecter_type(valeur)
    resultat = {
        "ioc": valeur,
        "type": type_ioc,
        "horodatage": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    if type_ioc is None:
        resultat["statut"] = "ignoré"
        resultat["raison"] = "format non reconnu"
        return resultat

    interne, raison = est_interne(valeur, type_ioc)
    if interne:
        resultat["statut"] = "local"
        resultat["raison"] = raison
        resultat["sources"] = {}
        return resultat

    sources = ROUTAGE.get(type_ioc, [])
    if dry_run:
        resultat["statut"] = "simulation"
        resultat["sortirait_vers"] = [nom for nom, _ in sources]
        return resultat

    resultat["statut"] = "enrichi"
    resultat["sources"] = {nom: fn(valeur) for nom, fn in sources}
    return resultat


def afficher_tableau(resultats):
    for r in resultats:
        marqueur = {"local": "[LOCAL]", "ignoré": "[SKIP] ", "simulation": "[DRY]  "}.get(r["statut"], "[OK]   ")
        print(f"\n{marqueur} {r['ioc']}  ({r['type'] or 'inconnu'})")
        if r["statut"] == "local":
            print(f"         non transmis — {r['raison']}")
            continue
        if r["statut"] == "ignoré":
            print(f"         {r['raison']}")
            continue
        if r["statut"] == "simulation":
            print(f"         serait transmis à : {', '.join(r['sortirait_vers']) or 'aucune source'}")
            continue
        for source, donnees in r["sources"].items():
            if "erreur" in donnees:
                print(f"         {source:<14} erreur : {donnees['erreur']}")
                continue
            champs = ", ".join(f"{k}={v}" for k, v in donnees.items() if v not in (None, [], ""))
            print(f"         {source:<14} {champs or 'aucune donnée'}")


def main():
    p = argparse.ArgumentParser(description="Enrichissement d'IOC depuis des sources publiques.")
    p.add_argument("iocs", nargs="*", help="IOC à enrichir (IP, domaine, hash)")
    p.add_argument("-f", "--fichier", help="fichier contenant un IOC par ligne")
    p.add_argument("--json", action="store_true", help="sortie JSON")
    p.add_argument("--dry-run", action="store_true",
                   help="n'émet aucune requête ; affiche ce qui sortirait du périmètre")
    args = p.parse_args()

    entrees = list(args.iocs)
    if args.fichier:
        with open(args.fichier, encoding="utf-8") as fh:
            entrees += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not entrees:
        p.error("aucun IOC fourni")

    resultats = [enrichir(v, dry_run=args.dry_run) for v in entrees]

    if args.json:
        print(json.dumps(resultats, indent=2, ensure_ascii=False))
    else:
        afficher_tableau(resultats)
        if not args.dry_run:
            print(f"\nAppels émis : {dict(LIMITEUR.appels) or 'aucun'}")


if __name__ == "__main__":
    main()
