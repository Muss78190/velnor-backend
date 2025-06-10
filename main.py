# -*- coding: utf-8 -*-
"""
main.py – Backend FastAPI pour VELNOR

Dépendances Python :
    pip install fastapi uvicorn python-dotenv stripe pydantic weasyprint apex-engine pdf-generator

Dépendances système (WeasyPrint sous Debian/Ubuntu) :
    sudo apt-get install libpango-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info

Variables d'environnement requises (.env) :
    STRIPE_SECRET_KEY, STRIPE_PRICE_24H, STRIPE_PRICE_48H,
    STRIPE_SUCCESS_URL (optionnel), STRIPE_CANCEL_URL (optionnel),
    CORS_ORIGINS (optionnel, séparées par des virgules)
"""
import os
import uuid
import logging
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv
import stripe

from apex_engine import analyse_cybersec
from pdf_generator import generate_pdf_report

# Chargement des variables d'environnement\load_dotenv()

# Configuration
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_24H = os.getenv("STRIPE_PRICE_24H", "price_1RPNODIbmxThmcuLyqMDzhWG")
STRIPE_PRICE_48H = os.getenv("STRIPE_PRICE_48H", "price_1RPNM8IbmxThmcuLS9Rr7nZT")
STRIPE_SUCCESS_URL = os.getenv("STRIPE_SUCCESS_URL", "https://velnor.fr/success")
STRIPE_CANCEL_URL = os.getenv("STRIPE_CANCEL_URL", "https://velnor.fr/cancel")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Initialisation de l'app
app = FastAPI(title="VELNOR API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration Stripe
if not STRIPE_SECRET_KEY:
    logger.error("STRIPE_SECRET_KEY non défini dans .env")
stripe.api_key = STRIPE_SECRET_KEY

# Répertoire des rapports PDF
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "rapports"
REPORTS_DIR.mkdir(exist_ok=True)

# Modèles Pydantic
class ScanRequest(BaseModel):
    url: str

# Monture des fichiers statiques pour les rapports
app.mount("/rapports", StaticFiles(directory=REPORTS_DIR), name="rapports")

@app.get("/", summary="Health check")
def root() -> Dict[str, str]:
    return {"message": "VELNOR backend opérationnel"}

@app.post("/scan", response_model=Dict[str, Any], summary="Lancer une analyse cybersécurité")
def scan_url(data: ScanRequest) -> Dict[str, Any]:
    """Effectue l'analyse puis génère et stocke le PDF du rapport."""
    try:
        logger.info(f"Démarrage de l'analyse pour {data.url}")
        result = analyse_cybersec(data.url)

        # Génération du PDF
        filename = f"audit_{uuid.uuid4().hex[:8]}.pdf"
        pdf_path = REPORTS_DIR / filename
        generate_pdf_report(result, str(pdf_path))

        # Ajout du lien PDF au résultat
        result["pdf"] = f"/rapports/{filename}"
        logger.info(f"Rapport PDF créé : {pdf_path}")
        return result

    except Exception as e:
        logger.exception("Erreur lors de l'analyse")
        raise HTTPException(status_code=500, detail=f"Erreur IA : {e}")

@app.post("/create-checkout-session-24h", summary="Session de paiement Stripe 24h")
def checkout_24h() -> Dict[str, str]:
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_24H, "quantity": 1}],
            mode="payment",
            success_url=STRIPE_SUCCESS_URL,
            cancel_url=STRIPE_CANCEL_URL,
        )
        return {"url": session.url}
    except Exception as e:
        logger.exception("Erreur Stripe 24h")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/create-checkout-session-48h", summary="Session de paiement Stripe 48h")
def checkout_48h() -> Dict[str, str]:
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_48H, "quantity": 1}],
            mode="payment",
            success_url=STRIPE_SUCCESS_URL,
            cancel_url=STRIPE_CANCEL_URL,
        )
        return {"url": session.url}
    except Exception as e:
        logger.exception("Erreur Stripe 48h")
        raise HTTPException(status_code=500, detail=str(e))

# Commande de lancement via Uvicorn
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
