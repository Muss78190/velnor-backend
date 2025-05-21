from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import stripe
import os

# Charger les variables d'environnement
load_dotenv()

app = FastAPI()

# Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Autoriser le frontend à accéder à l'API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # À restreindre à https://www.velnor.fr si tu veux plus tard
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 🔵 PAGE TEST (racine)
@app.get("/")
def read_root():
    return {"message": "Backend VELNOR opérationnel"}

# ✅ PAIEMENT 24h
@app.post("/create-checkout-session-24h")
async def create_checkout_session_24h():
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price": "price_1RPNODIbmxThmcuLyqMDzhWG",  # 24h
                "quantity": 1,
            }],
            mode="payment",
            success_url="https://velnor.fr/success",
            cancel_url="https://velnor.fr/cancel",
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ✅ PAIEMENT 48h
@app.post("/create-checkout-session-48h")
async def create_checkout_session_48h():
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price": "price_1RPNM8IbmxThmcuLS9Rr7nZT",  # 48h
                "quantity": 1,
            }],
            mode="payment",
            success_url="https://velnor.fr/success",
            cancel_url="https://velnor.fr/cancel",
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ✅ SCAN IA (admin)
class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
def scan_url(data: ScanRequest):
    url = data.url

    # 🔍 Simulation d’un audit
    fake_score = 82
    fake_resume = "Audit terminé avec 3 failles critiques détectées."
    recommendations = [
        "Mettre à jour le CMS.",
        "Configurer les headers de sécurité.",
        "Restreindre les accès aux ports exposés."
    ]

    pdf_path = "/rapport-audit-fictif.pdf"

    return {
        "url": url,
        "score": fake_score,
        "resume": fake_resume,
        "recommendations": recommendations,
        "pdf": pdf_path
    }

@app.get("/rapport-audit-fictif.pdf")
def get_fake_pdf():
    file_path = os.path.join(os.getcwd(), "rapport-audit-fictif.pdf")
    if os.path.exists(file_path):
        return FileResponse(path=file_path, filename="rapport-audit-fictif.pdf", media_type='application/pdf')
    return {"error": "Fichier PDF non trouvé"}
