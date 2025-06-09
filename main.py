from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import stripe
import os
import uuid

from apex_engine import analyse_cybersec
from pdf_generator import generate_pdf_report

load_dotenv()
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Stripe config
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

@app.get("/")
def root():
    return {"message": "VELNOR backend opérationnel"}

class ScanRequest(BaseModel):
    url: str

@app.post("/scan")
def scan_url(data: ScanRequest):
    try:
        print(f"[•] Analyse reçue pour : {data.url}")
        result = analyse_cybersec(data.url)

        filename = f"audit_{uuid.uuid4().hex[:8]}.pdf"
        pdf_path = os.path.join("rapports", filename)
        generate_pdf_report(result, pdf_path)

        result["pdf"] = f"/rapports/{filename}"
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur IA : {str(e)}")

@app.get("/rapports/{filename}")
def download_pdf(filename: str):
    path = os.path.join("rapports", filename)
    if os.path.exists(path):
        return FileResponse(path, media_type='application/pdf', filename=filename)
    raise HTTPException(status_code=404, detail="PDF non trouvé")

@app.post("/create-checkout-session-24h")
def checkout_24h():
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": "price_1RPNODIbmxThmcuLyqMDzhWG", "quantity": 1}],
            mode="payment",
            success_url="https://velnor.fr/success",
            cancel_url="https://velnor.fr/cancel"
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/create-checkout-session-48h")
def checkout_48h():
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": "price_1RPNM8IbmxThmcuLS9Rr7nZT", "quantity": 1}],
            mode="payment",
            success_url="https://velnor.fr/success",
            cancel_url="https://velnor.fr/cancel"
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
