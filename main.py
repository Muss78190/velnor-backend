from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import stripe
import os
from dotenv import load_dotenv

load_dotenv()
app = FastAPI()

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# CORS (permet au front d'accéder au back)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # à restreindre à ton domaine si besoin
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Backend VELNOR opérationnel"}

# ✅ Route 24h
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

# ✅ Route 48h
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
