# Backend VELNOR (FastAPI + Stripe)

## Lancement local
```
pip install -r requirements.txt
uvicorn main:app --reload
```

## Déploiement Railway
- Crée un projet
- Upload ce dossier
- Ajoute STRIPE_SECRET_KEY dans "Variables"
- Railway s'occupe du déploiement