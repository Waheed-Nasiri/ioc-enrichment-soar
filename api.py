#!/usr/bin/env python3
"""API HTTP minimale exposant l'enrichissement d'IOC à un SOAR."""

import os
from flask import Flask, request, jsonify
from enrich_ioc import enrichir

JETON = os.getenv("API_TOKEN", "")
app = Flask(__name__)


@app.get("/sante")
def sante():
    """Sonde de disponibilité, sans authentification."""
    return jsonify({"statut": "ok"})


@app.post("/enrich")
def enrich():
    # Sans jeton configuré, on refuse tout : pas d'ouverture par défaut.
    if not JETON or request.headers.get("X-Api-Token") != JETON:
        return jsonify({"erreur": "jeton invalide ou absent"}), 401

    corps = request.get_json(silent=True) or {}
    ioc = str(corps.get("ioc", "")).strip()
    if not ioc:
        return jsonify({"erreur": "champ 'ioc' manquant"}), 400

    return jsonify(enrichir(ioc))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8099)
