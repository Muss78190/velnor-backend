from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request
import stripe
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

# Autoriser le frontend à communiquer
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Clé secrète Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# Routes de paiement
@app.post("/create-checkout-session/24h")
async def create_checkout_session_24h():
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price": "price_1RPNM8IbmxThmcuLS9Rr7nZT",
                "quantity": 1,
            }],
            mode="payment",
            success_url="https://velnor.fr/success",
            cancel_url="https://velnor.fr/cancel",
        )
        return {"id": session.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/create-checkout-session/48h")
async def create_checkout_session_48h():
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price": "price_1RPNODIbmxThmcuLyqMDzhWG",
                "quantity": 1,
            }],
            mode="payment",
            success_url="https://velnor.fr/success",
            cancel_url="https://velnor.fr/cancel",
        )
        return {"id": session.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
