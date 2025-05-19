from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import stripe
import os

app = FastAPI()

# Autoriser les requêtes frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change "*" en https://velnor.fr pour + sécurité
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Clé Stripe depuis l'environnement
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

@app.post("/create-checkout-session")
def create_checkout_session(data: dict):
    try:
        price_id = data.get("price_id")
        if not price_id:
            raise HTTPException(status_code=400, detail="Missing price_id")

        session = stripe.checkout.Session.create(
            success_url="https://velnor.fr/success",
            cancel_url="https://velnor.fr/cancel",
            mode="payment",
            line_items=[{"price": price_id, "quantity": 1}]
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))