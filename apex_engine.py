import re
import requests

CVE_DATABASE = {
    "Apache/2.4.49": {"cve": "CVE-2021-41773", "critique": True, "description": "Faille RCE via path traversal."},
    "nginx/1.20.1": {"cve": "CVE-2021-23017", "critique": True, "description": "Vulnérabilité sur en-tête HTTP."},
    "OpenSSH_7.2p2": {"cve": "CVE-2016-10009", "critique": False, "description": "Injection via scp."}
}

COMMON_PATHS = ["/admin", "/login", "/.git", "/backup", "/db.sql", "/config", "/.env"]
HEADERS_SECURITE = {
    "Content-Security-Policy": "Protège contre XSS",
    "Strict-Transport-Security": "Force HTTPS",
    "X-Content-Type-Options": "Contre MIME-sniffing",
    "X-Frame-Options": "Contre clickjacking",
    "Referrer-Policy": "Protège vie privée",
    "Permissions-Policy": "Limite accès aux API"
}

def analyse_cybersec(url: str):
    score_vectoriel = {
        "ports": 0, "services_critiques": 0, "cve": 0,
        "headers": 0, "html": 0, "cms": 0, "chemins": 0,
        "xss_sqli": 0, "js_dangereux": 0, "fichiers_exposes": 0
    }
    recommandations = []
    anomalies = []

    # Ports simulés
    ports = [("80", "http"), ("443", "https")]
    for port, service in ports:
        anomalies.append(f"Port {port}/tcp ouvert : {service}")
        score_vectoriel["ports"] += 3
        if service in ["ftp", "telnet", "ssh", "smtp", "mysql", "rdp"]:
            recommandations.append(f"🚨 Service critique ouvert : {service.upper()} sur {port}")
            score_vectoriel["services_critiques"] += 7

    # CVE simulées
    for version, data in CVE_DATABASE.items():
        if version in url:
            anomalies.append(f"{version} → Vulnérabilité connue ({data['cve']})")
            score_vectoriel["cve"] += 15 if data["critique"] else 7
            recommandations.append(f"{'🚨' if data['critique'] else '⚠️'} {version} vulnérable : {data['description']}")

    try:
        r = requests.get(url, timeout=6)
        headers = r.headers
        content = r.text.lower()

        for h, why in HEADERS_SECURITE.items():
            if h not in headers:
                recommandations.append(f"🔐 Header manquant : {h} ({why})")
                score_vectoriel["headers"] += 5

        techno = []
        if "x-powered-by" in headers:
            techno.append(headers["x-powered-by"])
        if "<meta name=\"generator\"" in content:
            match = re.search(r'<meta name="generator" content="([^"]+)', content)
            if match:
                techno.append(match.group(1))
        if "wp-content" in content or "wordpress" in content:
            techno.append("WordPress")
        if "laravel" in content or "symfony" in content:
            techno.append("Laravel/Symfony")
        if techno:
            recommandations.append(f"ℹ️ Technologies détectées : {', '.join(set(techno))}")
            score_vectoriel["cms"] += 5

        if any(js in content for js in ["eval(", "document.write", "innerhtml"]):
            anomalies.append("⚠️ JS potentiellement dangereux trouvé")
            score_vectoriel["js_dangereux"] += 6
            recommandations.append("⚠️ Nettoyez vos scripts JS (évitez eval, document.write...)")

        accessibles = []
        for path in COMMON_PATHS:
            try:
                resp = requests.get(url.rstrip("/") + path, timeout=3)
                if resp.status_code == 200:
                    accessibles.append(path)
                    score_vectoriel["chemins"] += 4
            except:
                continue
        if accessibles:
            recommandations.append(f"🚫 Chemins sensibles accessibles : {', '.join(accessibles)}")

        payloads = {"XSS": "<script>alert(1)</script>", "SQLi": "' OR '1'='1"}
        for name, payload in payloads.items():
            try:
                res = requests.get(url, params={"v": payload}, timeout=4)
                if payload in res.text:
                    recommandations.append(f"⚠️ Vulnérabilité {name} détectée via GET")
                    score_vectoriel["xss_sqli"] += 10
            except:
                continue

        exposés = []
        for f in [".env", ".git", "config.php", "backup.sql"]:
            try:
                res = requests.get(url.rstrip("/") + "/" + f, timeout=3)
                if res.status_code == 200 and len(res.text) > 20:
                    exposés.append(f)
                    score_vectoriel["fichiers_exposes"] += 6
            except:
                continue
        if exposés:
            anomalies.append(f"📂 Fichiers sensibles exposés : {', '.join(exposés)}")
            recommandations.append("🚨 Supprimez ou protégez ces fichiers immédiatement.")

    except Exception as e:
        anomalies.append(f"🌐 Erreur HTTP : {e}")
        score_vectoriel["html"] += 5

    score = max(0, 100 - sum(score_vectoriel.values()))

    if score >= 90:
        resume = "✅ Site globalement sécurisé."
    elif score >= 70:
        resume = "⚠️ Quelques failles à corriger."
    elif score >= 50:
        resume = "⚠️ Plusieurs vulnérabilités détectées."
    else:
        resume = "❌ Site à risque élevé. Intervention urgente recommandée."

    return {
        "url": url,
        "score": score,
        "resume": resume,
        "anomalies": anomalies,
        "recommendations": recommandations
    }
