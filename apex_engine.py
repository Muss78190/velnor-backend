# apex_engine.py

import re
import time
import requests
import nmap
from zapv2 import ZAPv2

# ==== BASES DE DONNÉES ====

CVE_DATABASE = {
    "Apache/2.4.49": {
        "cve": "CVE-2021-41773",
        "critique": True,
        "description": "Faille RCE via path traversal."
    },
    "nginx/1.20.1": {
        "cve": "CVE-2021-23017",
        "critique": True,
        "description": "Vulnérabilité sur en-tête HTTP."
    },
    "OpenSSH_7.2p2": {
        "cve": "CVE-2016-10009",
        "critique": False,
        "description": "Injection via scp."
    }
}

COMMON_PATHS = [
    "/admin", "/login", "/.git", "/backup", "/db.sql", "/config", "/.env"
]

HEADERS_SECURITE = {
    "Content-Security-Policy": "Protège contre XSS",
    "Strict-Transport-Security": "Force HTTPS",
    "X-Content-Type-Options": "Contre MIME-sniffing",
    "X-Frame-Options": "Contre clickjacking",
    "Referrer-Policy": "Protège vie privée",
    "Permissions-Policy": "Limite accès aux API"
}


# ==== FONCTION PRINCIPALE ====

def analyse_cybersec(url: str):
    """
    Analyse complète de cybersécurité :
      - scan Nmap (ports)
      - spider + active scan ZAP
      - vérification HTTP (headers, payloads, fichiers exposés)
      - détection de CVE connues
      - scoring global et recommandations
    """

    # Initialisation
    anomalies = []
    recommandations = []
    score = {
        "ports": 0,
        "zapprobe": 0,
        "headers": 0,
        "cve": 0,
        "xss_sqli": 0,
        "chemins": 0,
        "html": 0,
        "fichiers_exposes": 0
    }

    # 1) SCAN DE PORTS AVEC NMAP
    try:
        nm = nmap.PortScanner()
        target = url.replace("https://", "").replace("http://", "").split("/")[0]
        nm.scan(hosts=target, arguments="-Pn -p 1-1024")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port, info in nm[host][proto].items():
                    state = info["state"]
                    anomalies.append(f"Port {port}/{proto} → {state}")
                    if state == "open":
                        score["ports"] += 3
    except Exception as e:
        anomalies.append(f"Erreur Nmap : {e}")

    # 2) SPIDER + ACTIVE SCAN OWASP ZAP
    try:
        zap = ZAPv2(proxies={"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"})
        zap.urlopen(url)
        time.sleep(2)

        # Spider
        spider_id = zap.spider.scan(url)
        while int(zap.spider.status(spider_id)) < 100:
            time.sleep(1)

        # Active scan
        ascan_id = zap.ascan.scan(url)
        while int(zap.ascan.status(ascan_id)) < 100:
            time.sleep(2)

        # Récupère les alertes
        for alert in zap.core.alerts(baseurl=url):
            risk = alert["risk"]       # "Low", "Medium", "High"
            anomalies.append(f"ZAP [{risk}] : {alert['alert']}")
            recommandations.append(f"Solution ZAP : {alert['solution']}")
            # Pondération simple selon criticité
            score["zapprobe"] += {"Low": 5, "Medium": 10, "High": 15}[risk]
    except Exception as e:
        anomalies.append(f"Erreur ZAP : {e}")

    # 3) ANALYSE HTTP (headers, contenu, payloads)
    try:
        resp = requests.get(url, timeout=10)
        headers = resp.headers
        content = resp.text.lower()

        # a) Headers de sécurité manquants
        for h, desc in HEADERS_SECURITE.items():
            if h not in headers:
                recommandations.append(f"Header manquant : {h} ({desc})")
                score["headers"] += 5

        # b) CVE connues
        server_hdr = headers.get("Server", "")
        for version, info in CVE_DATABASE.items():
            if version in server_hdr or version.lower() in content:
                crit = info["critique"]
                anomalies.append(f"{version} → {info['cve']}")
                score["cve"] += 15 if crit else 7
                recommandations.append(f"{info['description']}")

        # c) JS dangereux
        for pattern in ["eval(", "document.write", "innerhtml"]:
            if pattern in content:
                anomalies.append("⚠️ JS potentiellement dangereux")
                score["xss_sqli"] += 6
                recommandations.append("Sanbox ou nettoyage des scripts JS")

        # d) Paths sensibles
        found = []
        for path in COMMON_PATHS:
            try:
                r = requests.get(url.rstrip("/") + path, timeout=4)
                if r.status_code == 200:
                    found.append(path)
                    score["chemins"] += 4
            except:
                pass
        if found:
            recommandations.append("Chemins sensibles accessibles : " + ", ".join(found))

        # e) XSS / SQLi basique
        payloads = {"XSS": "<script>alert(1)</script>", "SQLi": "' OR '1'='1"}
        for name, pl in payloads.items():
            try:
                r = requests.get(url, params={"v": pl}, timeout=5)
                if pl in r.text:
                    anomalies.append(f"⚠️ Vulnérabilité {name} détectée")
                    score["xss_sqli"] += 10
            except:
                pass

        # f) Fichiers exposés
        exposed = []
        for f in [".env", ".git", "config.php", "backup.sql"]:
            try:
                r = requests.get(url.rstrip("/") + "/" + f, timeout=4)
                if r.status_code == 200 and len(r.text) > 20:
                    exposed.append(f)
                    score["fichiers_exposes"] += 6
            except:
                pass
        if exposed:
            anomalies.append("Fichiers exposés : " + ", ".join(exposed))
            recommandations.append("Protégez ou supprimez ces fichiers")
    except Exception as e:
        anomalies.append(f"Erreur HTTP : {e}")
        score["html"] += 5

    # 4) CALCUL DU SCORE & RÉSUMÉ
    total_penalty = sum(score.values())
    final_score = max(0, 100 - total_penalty)

    if final_score >= 90:
        resume = "✅ Site globalement sécurisé."
    elif final_score >= 70:
        resume = "⚠️ Quelques failles à corriger."
    elif final_score >= 50:
        resume = "⚠️ Plusieurs vulnérabilités détectées."
    else:
        resume = "❌ Site à risque élevé. Intervention urgente requise."

    return {
        "url": url,
        "score": final_score,
        "resume": resume,
        "anomalies": anomalies,
        "recommendations": recommandations
    }
