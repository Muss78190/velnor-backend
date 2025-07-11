import os
import uuid
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from fastapi import FastAPI, HTTPException, Request  # ⭐ AJOUTÉ Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import stripe

from apex_engine import analyse_cybersec
from pdf_generator import generate_pdf_report

# Chargement des variables d'environnement
load_dotenv()

# STRIPE - Configuration sécurisée
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_24H = os.getenv("STRIPE_PRICE_24H", "price_XXX")
STRIPE_PRICE_48H = os.getenv("STRIPE_PRICE_48H", "price_YYY")
STRIPE_SUCCESS_URL = os.getenv("STRIPE_SUCCESS_URL", "https://velnor.fr/success")
STRIPE_CANCEL_URL = os.getenv("STRIPE_CANCEL_URL", "https://velnor.fr/cancel")

# ⭐ VALIDATION ET CONFIGURATION STRIPE
if not STRIPE_SECRET_KEY:
    print("❌ ERREUR CRITIQUE: STRIPE_SECRET_KEY manquante dans .env")
    raise ValueError("STRIPE_SECRET_KEY est obligatoire pour démarrer l'application")

# Configuration de l'API Stripe
stripe.api_key = STRIPE_SECRET_KEY
print(f"✅ Stripe configuré avec clé: {STRIPE_SECRET_KEY[:20]}...")

# Debug info (à retirer en production)
print(f"🔑 STRIPE_SECRET_KEY chargée: {STRIPE_SECRET_KEY[:20]}...")
print(f"📁 Répertoire de travail: {os.getcwd()}")
print(f"📄 Fichier .env existe: {os.path.exists('.env')}")

# Logger global
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("velnor")

# App FastAPI
app = FastAPI(title="VELNOR API", version="2.0.0")

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://.*\.?velnor\.fr",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Type", "Authorization", "Access-Control-Allow-Origin"]
)

if not STRIPE_SECRET_KEY:
    logger.error("⚠️ STRIPE_SECRET_KEY non défini dans .env")
stripe.api_key = STRIPE_SECRET_KEY

# Répertoires
BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "rapports"
REPORTS_DIR.mkdir(exist_ok=True)
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

app.mount("/rapports", StaticFiles(directory=REPORTS_DIR), name="rapports")

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    status: str
    task_id: str
    message: str

# ⭐ NOUVEAU MODÈLE pour les paiements
class CheckoutRequest(BaseModel):
    url: str
    email: str
    nom: str
    entreprise: str = ""  # Optionnel

@app.get("/")
def root() -> Dict[str, str]:
    return {"message": "VELNOR backend opérationnel v2.0", "status": "running"}

@app.get("/health")
def health_check() -> Dict[str, str]:
    """Endpoint de santé pour vérifier que le service fonctionne"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

# 🆕 NOUVELLE ROUTE POUR TÉLÉCHARGER LES PDFs
@app.get("/download-pdf/{task_id}")
async def download_pdf(task_id: str):
    """
    Télécharge le rapport PDF d'un audit cybersécurité
    """
    try:
        logger.info(f"[{task_id}] 📄 Demande de téléchargement PDF")
        
        # Chemin du PDF
        pdf_path = REPORTS_DIR / task_id / "audit.pdf"
        
        # Vérifier si le fichier existe
        if not pdf_path.exists():
            logger.error(f"[{task_id}] ❌ PDF non trouvé: {pdf_path}")
            raise HTTPException(status_code=404, detail="Rapport PDF non trouvé")
        
        # Nom du fichier pour le téléchargement
        filename = f"velnor_audit_{task_id}.pdf"
        
        logger.info(f"[{task_id}] ✅ PDF trouvé, envoi du fichier")
        
        return FileResponse(
            path=str(pdf_path),
            filename=filename,
            media_type='application/pdf',
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "application/pdf"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{task_id}] ❌ Erreur téléchargement PDF: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur lors du téléchargement du PDF")

# 🆕 ROUTE ALTERNATIVE POUR VÉRIFIER SI LE PDF EXISTE
@app.get("/pdf-ready/{task_id}")
async def check_pdf_ready(task_id: str) -> Dict[str, Any]:
    """
    Vérifie si le PDF est prêt pour téléchargement
    """
    try:
        pdf_path = REPORTS_DIR / task_id / "audit.pdf"
        
        if pdf_path.exists():
            file_size = pdf_path.stat().st_size
            return {
                "ready": True,
                "task_id": task_id,
                "file_size": file_size,
                "download_url": f"/download-pdf/{task_id}"
            }
        else:
            return {
                "ready": False,
                "task_id": task_id,
                "message": "PDF en cours de génération"
            }
            
    except Exception as e:
        logger.error(f"[{task_id}] Erreur vérification PDF: {str(e)}")
        return {
            "ready": False,
            "task_id": task_id,
            "error": str(e)
        }

# ThreadPoolExecutor global avec gestion d'erreurs améliorée
executor = ThreadPoolExecutor(max_workers=3, thread_name_prefix="velnor_scan")

def validate_url(url: str) -> tuple[bool, str]:
    """Valide et normalise une URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Test de connectivité basique
        resp = requests.head(url, timeout=10, allow_redirects=True)
        if resp.status_code >= 400:
            return False, f"URL retourne status {resp.status_code}"
        
        return True, url
    except requests.exceptions.ConnectionError:
        return False, "Impossible de se connecter à l'URL"
    except requests.exceptions.Timeout:
        return False, "Timeout lors de la connexion"
    except requests.exceptions.InvalidURL:
        return False, "Format d'URL invalide"
    except Exception as e:
        return False, f"Erreur validation URL: {str(e)}"

def execute_cybersec_analysis(url: str, task_id: str, audit_dir: Path) -> None:
    """
    Exécute l'analyse cybersécurité dans un thread séparé avec gestion d'erreurs complète
    """
    json_path = audit_dir / "result.json"
    pdf_path = audit_dir / "audit.pdf"
    
    # Logger spécifique pour cette tâche
    task_logger = logging.getLogger(f"velnor.task.{task_id}")
    task_logger.setLevel(logging.INFO)
    
    # Éviter les doublons de handlers
    if not task_logger.handlers:
        task_log_path = LOGS_DIR / f"main_logs_{task_id}.txt"
        file_handler = logging.FileHandler(task_log_path)
        formatter = logging.Formatter("%(asctime)s [MAIN] %(levelname)s %(message)s")
        file_handler.setFormatter(formatter)
        task_logger.addHandler(file_handler)
    
    start_time = datetime.utcnow()
    
    try:
        task_logger.info(f"=== DÉBUT THREAD ANALYSE - Task ID: {task_id} ===")
        task_logger.info(f"URL: {url}")
        task_logger.info(f"Répertoire audit: {audit_dir}")
        
        # Phase 1: Validation URL approfondie
        task_logger.info("Phase 1: Validation URL approfondie...")
        try:
            resp = requests.get(url, timeout=15, verify=False)
            resp.raise_for_status()
            task_logger.info(f"URL accessible - Status: {resp.status_code}")
        except Exception as e:
            error_msg = f"URL non accessible: {str(e)}"
            task_logger.error(error_msg)
            
            # Résultat d'erreur minimal
            result = {
                "status": "failed",
                "task_id": task_id,
                "url": url,
                "error": error_msg,
                "score": 0,
                "niveau_risque": "Erreur",
                "resume": "❌ URL inaccessible",
                "anomalies": [error_msg],
                "recommendations": ["Vérifier que l'URL est correcte et accessible"],
                "failles": [],
                "failures": [{"phase": "url_validation", "type": "ConnectionError", "message": error_msg}],
                "phase_results": {"url_validation": {"status": "failed", "error": error_msg}},
                "details_score": {"total": 0},
                "statistiques": {
                    "nb_anomalies": 1,
                    "nb_recommendations": 1,
                    "nb_failles": 0,
                    "nb_failures": 1,
                    "phases_success": 0,
                    "phases_failed": 1,
                    "duree_analyse": (datetime.utcnow() - start_time).total_seconds(),
                    "timestamp": datetime.utcnow().isoformat()
                },
                "metadata": {
                    "version": "2.0",
                    "engine": "velnor_main",
                    "log_file": f"logs/main_logs_{task_id}.txt"
                }
            }
            
            with open(json_path, "w", encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            task_logger.info("Résultat d'erreur sauvegardé")
            return

        # Phase 2: Analyse cybersécurité avec notre engine robuste
        task_logger.info("Phase 2: Lancement analyse cybersécurité...")
        
        # Appel à notre fonction ultra-robuste
        result_data = analyse_cybersec(url, task_id)
        
        task_logger.info(f"Analyse terminée - Status: {result_data.get('status', 'unknown')}")
        task_logger.info(f"Score obtenu: {result_data.get('score', 0)}/100")
        task_logger.info(f"Failles détectées: {len(result_data.get('failles', []))}")
        
        # Phase 3: Génération PDF
        task_logger.info("Phase 3: Génération du rapport PDF...")
        
        try:
            generate_pdf_report(result_data, str(pdf_path))
            task_logger.info(f"PDF généré avec succès: {pdf_path}")
            pdf_generated = True
        except Exception as e:
            task_logger.error(f"Erreur génération PDF: {str(e)}")
            pdf_generated = False
            result_data["pdf_error"] = str(e)

        # Phase 4: Finalisation et sauvegarde
        finished_time = datetime.utcnow()
        duration = (finished_time - start_time).total_seconds()
        
        # Enrichissement des métadonnées
        result_data.update({
            "pdf": f"/download-pdf/{task_id}" if pdf_generated else None,  # 🆕 Nouvelle URL
            "pdf_generated": pdf_generated,
            "started_at": start_time.isoformat(),
            "finished_at": finished_time.isoformat(),
            "duration_seconds": duration
        })
        
        # Mise à jour des statistiques si elles existent
        if "statistiques" in result_data:
            result_data["statistiques"]["duration_total"] = duration
            result_data["statistiques"]["pdf_generated"] = pdf_generated
        
        # Sauvegarde du résultat
        with open(json_path, "w", encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        
        task_logger.info(f"=== ANALYSE TERMINÉE AVEC SUCCÈS ===")
        task_logger.info(f"Durée totale: {duration:.2f}s")
        task_logger.info(f"Fichiers générés: JSON ✓, PDF {'✓' if pdf_generated else '✗'}")
        
    except Exception as e:
        # Gestion d'erreur de dernier recours
        task_logger.exception(f"ERREUR CRITIQUE DANS LE THREAD: {str(e)}")
        
        error_result = {
            "status": "error",
            "task_id": task_id,
            "url": url,
            "error": f"Erreur critique: {str(e)}",
            "score": 0,
            "niveau_risque": "Erreur critique",
            "resume": "❌ Erreur système lors de l'analyse",
            "anomalies": [f"Erreur système: {str(e)}"],
            "recommendations": ["Contacter le support technique"],
            "failles": [],
            "failures": [{"phase": "system", "type": "CriticalError", "message": str(e)}],
            "phase_results": {},
            "details_score": {},
            "statistiques": {
                "nb_anomalies": 1,
                "nb_recommendations": 1,
                "nb_failles": 0,
                "nb_failures": 1,
                "phases_success": 0,
                "phases_failed": 1,
                "duree_analyse": (datetime.utcnow() - start_time).total_seconds(),
                "timestamp": datetime.utcnow().isoformat()
            },
            "metadata": {
                "version": "2.0",
                "engine": "velnor_main_error",
                "log_file": f"logs/main_logs_{task_id}.txt"
            }
        }
        
        try:
            with open(json_path, "w", encoding='utf-8') as f:
                json.dump(error_result, f, indent=2, ensure_ascii=False)
        except Exception as save_error:
            task_logger.error(f"Impossible de sauvegarder le résultat d'erreur: {save_error}")
    
    finally:
        # Nettoyage des handlers pour éviter les fuites mémoire
        for handler in task_logger.handlers[:]:
            handler.close()
            task_logger.removeHandler(handler)

@app.post("/scan", response_model=ScanResponse)
def scan_url(data: ScanRequest) -> ScanResponse:
    """
    Endpoint principal pour lancer un audit cybersécurité
    Version ultra-robuste avec gestion d'erreurs complète
    """
    try:
        # Génération task_id unique
        task_id = uuid.uuid4().hex[:8]
        
        logger.info(f"[{task_id}] 📥 Nouvelle demande d'audit reçue")
        logger.info(f"[{task_id}] 🎯 URL demandée: {data.url}")
        
        # Validation préliminaire de l'URL
        is_valid, validated_url_or_error = validate_url(data.url)
        if not is_valid:
            logger.error(f"[{task_id}] ❌ URL invalide: {validated_url_or_error}")
            return ScanResponse(
                status="error",
                task_id=task_id,
                message=f"URL invalide: {validated_url_or_error}"
            )
        
        validated_url = validated_url_or_error
        logger.info(f"[{task_id}] ✅ URL validée: {validated_url}")
        
        # Création du répertoire d'audit
        audit_dir = REPORTS_DIR / task_id
        audit_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"[{task_id}] 📁 Répertoire créé: {audit_dir}")
        
        # Soumission du travail au ThreadPoolExecutor
        try:
            future = executor.submit(execute_cybersec_analysis, validated_url, task_id, audit_dir)
            logger.info(f"[{task_id}] 🚀 Thread d'analyse soumis avec succès")
            
            return ScanResponse(
                status="en_cours",
                task_id=task_id,
                message=f"Analyse cybersécurité démarrée pour {validated_url}"
            )
            
        except Exception as executor_error:
            logger.error(f"[{task_id}] ❌ Erreur soumission thread: {str(executor_error)}")
            return ScanResponse(
                status="error",
                task_id=task_id,
                message=f"Erreur interne: impossible de démarrer l'analyse"
            )
    
    except Exception as e:
        # Gestion d'erreur globale de l'endpoint
        error_task_id = uuid.uuid4().hex[:8]
        logger.exception(f"[{error_task_id}] ❌ ERREUR CRITIQUE ENDPOINT /scan: {str(e)}")
        
        return ScanResponse(
            status="error",
            task_id=error_task_id,
            message="Erreur serveur interne"
        )

@app.get("/scan-result/{task_id}")
def get_scan_result(task_id: str) -> Dict[str, Any]:
    """
    Récupère le résultat d'un scan par son task_id
    Version améliorée avec gestion d'erreurs
    """
    try:
        logger.info(f"[{task_id}] 📊 Demande de résultat")
        
        json_path = REPORTS_DIR / task_id / "result.json"
        
        if not json_path.exists():
            logger.info(f"[{task_id}] ⏳ Analyse en cours (pas de résultat)")
            return {
                "status": "en_cours",
                "task_id": task_id,
                "message": "Analyse en cours d'exécution"
            }
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                result = json.load(f)
                
            logger.info(f"[{task_id}] ✅ Résultat trouvé et retourné")
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"[{task_id}] ❌ Erreur lecture JSON: {str(e)}")
            return {
                "status": "error",
                "task_id": task_id,
                "error": "Fichier de résultat corrompu",
                "message": "Erreur lors de la lecture du résultat"
            }
            
    except Exception as e:
        logger.exception(f"[{task_id}] ❌ Erreur récupération résultat: {str(e)}")
        return {
            "status": "error", 
            "task_id": task_id,
            "error": "Erreur serveur",
            "message": "Erreur lors de la récupération du résultat"
        }

@app.get("/scan-status/{task_id}")
def get_scan_status(task_id: str) -> Dict[str, Any]:
    """
    Endpoint pour vérifier uniquement le status d'un scan (plus léger)
    """
    try:
        json_path = REPORTS_DIR / task_id / "result.json"
        
        if not json_path.exists():
            return {"status": "en_cours", "task_id": task_id}
        
        with open(json_path, 'r', encoding='utf-8') as f:
            result = json.load(f)
        
        return {
            "status": result.get("status", "unknown"),
            "task_id": task_id,
            "score": result.get("score", 0),
            "niveau_risque": result.get("niveau_risque", "Inconnu"),
            "nb_failles": len(result.get("failles", [])),
            "duration": result.get("duration_seconds", 0)
        }
        
    except Exception as e:
        logger.error(f"[{task_id}] Erreur status: {str(e)}")
        return {"status": "error", "task_id": task_id}

# ⭐ ENDPOINTS STRIPE CORRIGÉS
@app.post("/create-checkout-session-24h")
def checkout_24h(data: CheckoutRequest) -> Dict[str, str]:
    """
    Crée une session Stripe pour l'audit 24h avec les données client
    """
    try:
        logger.info(f"🚀 Début création session 24h pour: {data.url} - {data.email}")
        
        # ⭐ DEBUG COMPLET
        logger.info(f"🔍 STRIPE_SECRET_KEY = {STRIPE_SECRET_KEY[:20] if STRIPE_SECRET_KEY else 'NONE'}...")
        logger.info(f"🔍 Type STRIPE_SECRET_KEY = {type(STRIPE_SECRET_KEY)}")
        logger.info(f"🔍 STRIPE_SECRET_KEY is None? = {STRIPE_SECRET_KEY is None}")
        
        # ⭐ VALIDATION CLÉ AVANT IMPORT
        if not STRIPE_SECRET_KEY or STRIPE_SECRET_KEY == "":
            raise HTTPException(status_code=500, detail="Configuration Stripe manquante")
        
        # ⭐ IMPORT STRIPE LOCAL
        import stripe as st
        logger.info(f"🔍 stripe module importé = {st}")
        logger.info(f"🔍 stripe.checkout avant = {getattr(st, 'checkout', 'PAS_TROUVÉ')}")
        
        # ⭐ CONFIGURATION API KEY
        st.api_key = STRIPE_SECRET_KEY
        logger.info(f"🔍 st.api_key configuré = {st.api_key[:20] if st.api_key else 'NONE'}...")
        
        # ⭐ VALIDATION DONNÉES
        if not data.url or not data.url.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="URL invalide - doit commencer par http:// ou https://")
        
        if "@" not in data.email:
            raise HTTPException(status_code=400, detail="Email invalide")
        
        # ⭐ VALIDATION PRICE ID
        if not STRIPE_PRICE_24H or STRIPE_PRICE_24H == "price_XXX":
            raise HTTPException(status_code=500, detail="Price ID 24h non configuré")
        
        logger.info(f"🔍 Création session avec price: {STRIPE_PRICE_24H}")
        
        # ⭐ CRÉATION SESSION STRIPE
        session = st.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_24H, "quantity": 1}],
            mode="payment",
            success_url=STRIPE_SUCCESS_URL + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=STRIPE_CANCEL_URL,
            customer_email=data.email,
            metadata={
                "url": data.url,
                "nom": data.nom,
                "entreprise": data.entreprise,
                "type": "audit_24h",
                "email": data.email
            }
        )
        
        logger.info(f"✅ Session 24h créée avec succès: {session.id}")
        logger.info(f"✅ URL de redirection: {session.url}")
        
        return {"url": session.url}
        
    except stripe.error.StripeError as e:
        error_msg = f"Erreur Stripe 24h: {str(e)}"
        logger.error(f"❌ {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)
    except HTTPException:
        raise  # Re-raise les HTTPException sans les wrapper
    except Exception as e:
        error_msg = f"Erreur système 24h: {str(e)}"
        logger.error(f"❌ {error_msg}")
        logger.exception("Stack trace complète:")
        raise HTTPException(status_code=500, detail=error_msg)

@app.post("/create-checkout-session-48h")
def checkout_48h(data: CheckoutRequest) -> Dict[str, str]:
    """
    Crée une session Stripe pour l'audit 48h avec les données client
    """
    try:
        logger.info(f"🚀 Début création session 48h pour: {data.url} - {data.email}")
        
        # ⭐ DEBUG COMPLET
        logger.info(f"🔍 STRIPE_SECRET_KEY = {STRIPE_SECRET_KEY[:20] if STRIPE_SECRET_KEY else 'NONE'}...")
        logger.info(f"🔍 Type STRIPE_SECRET_KEY = {type(STRIPE_SECRET_KEY)}")
        logger.info(f"🔍 STRIPE_SECRET_KEY is None? = {STRIPE_SECRET_KEY is None}")
        
        # ⭐ VALIDATION CLÉ AVANT IMPORT
        if not STRIPE_SECRET_KEY or STRIPE_SECRET_KEY == "":
            raise HTTPException(status_code=500, detail="Configuration Stripe manquante")
        
        # ⭐ IMPORT STRIPE LOCAL
        import stripe as st
        logger.info(f"🔍 stripe module importé = {st}")
        logger.info(f"🔍 stripe.checkout avant = {getattr(st, 'checkout', 'PAS_TROUVÉ')}")
        
        # ⭐ CONFIGURATION API KEY
        st.api_key = STRIPE_SECRET_KEY
        logger.info(f"🔍 st.api_key configuré = {st.api_key[:20] if st.api_key else 'NONE'}...")
        
        # ⭐ VALIDATION DONNÉES
        if not data.url or not data.url.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="URL invalide - doit commencer par http:// ou https://")
        
        if "@" not in data.email:
            raise HTTPException(status_code=400, detail="Email invalide")
        
        # ⭐ VALIDATION PRICE ID
        if not STRIPE_PRICE_48H or STRIPE_PRICE_48H == "price_YYY":
            raise HTTPException(status_code=500, detail="Price ID 48h non configuré")
        
        logger.info(f"🔍 Création session avec price: {STRIPE_PRICE_48H}")
        
        # ⭐ CRÉATION SESSION STRIPE
        session = st.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_PRICE_48H, "quantity": 1}],
            mode="payment",
            success_url=STRIPE_SUCCESS_URL + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=STRIPE_CANCEL_URL,
            customer_email=data.email,
            metadata={
                "url": data.url,
                "nom": data.nom,
                "entreprise": data.entreprise,
                "type": "audit_48h",
                "email": data.email
            }
        )
        
        logger.info(f"✅ Session 48h créée avec succès: {session.id}")
        logger.info(f"✅ URL de redirection: {session.url}")
        
        return {"url": session.url}
        
    except stripe.error.StripeError as e:
        error_msg = f"Erreur Stripe 48h: {str(e)}"
        logger.error(f"❌ {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)
    except HTTPException:
        raise  # Re-raise les HTTPException sans les wrapper
    except Exception as e:
        error_msg = f"Erreur système 48h: {str(e)}"
        logger.error(f"❌ {error_msg}")
        logger.exception("Stack trace complète:")
        raise HTTPException(status_code=500, detail=error_msg)

# ⭐ NOUVEAU : Webhook pour auto-lancement après paiement (optionnel pour plus tard)
@app.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    """
    Webhook Stripe pour lancer automatiquement l'audit après paiement
    """
    try:
        payload = await request.body()
        sig_header = request.headers.get('stripe-signature')
        
        # ⚠️ À configurer dans Stripe Dashboard plus tard
        endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_XXX")
        
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
        
        logger.info(f"🎯 Webhook Stripe reçu: {event['type']}")
        
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            
            # Récupérer les métadonnées
            url = session['metadata'].get('url')
            email = session['metadata'].get('email', session.get('customer_email'))
            nom = session['metadata'].get('nom', 'Client')
            audit_type = session['metadata'].get('type', 'audit_24h')
            
            logger.info(f"💰 Paiement confirmé - {audit_type} pour {url} - {email}")
            
            # TODO: Ici tu peux lancer l'audit automatiquement
            # ou envoyer un email de confirmation
            
        return {"status": "success"}
        
    except Exception as e:
        logger.error(f"❌ Erreur webhook: {e}")
        raise HTTPException(status_code=400, detail=str(e))

# Endpoint pour nettoyer les anciens fichiers (optionnel)
@app.post("/admin/cleanup")
def cleanup_old_reports(days: int = 7) -> Dict[str, Any]:
    """
    Nettoie les rapports de plus de X jours (endpoint admin)
    """
    try:
        from datetime import timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        cleaned = 0
        for task_dir in REPORTS_DIR.iterdir():
            if task_dir.is_dir():
                try:
                    dir_time = datetime.fromtimestamp(task_dir.stat().st_mtime)
                    if dir_time < cutoff_date:
                        import shutil
                        shutil.rmtree(task_dir)
                        cleaned += 1
                except Exception:
                    continue
        
        return {"cleaned": cleaned, "days": days}
    except Exception as e:
        logger.error(f"Erreur cleanup: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 10000))
    logger.info(f"🚀 Démarrage VELNOR backend v2.0 sur port {port}")
    uvicorn.run("main:app", host="0.0.0.0", port=port)