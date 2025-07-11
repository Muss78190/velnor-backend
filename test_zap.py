import requests

proxies = {
    "http": "http://127.0.0.1:8090",
    "https": "http://127.0.0.1:8090"
}

try:
    response = requests.get("https://www.google.com", proxies=proxies, verify=False, timeout=10)
    print("[✅] Réponse ZAP proxy : ", response.status_code)
except Exception as e:
    print("[❌] ZAP proxy ne répond pas :", e)
