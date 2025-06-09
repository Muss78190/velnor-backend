from zapv2 import ZAPv2

# Connexion à ZAP via le proxy en localhost:8090
zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})

# Vérifie la connexion
print("Connexion réussie à ZAP !")
print("Version ZAP :", zap.core.version)
