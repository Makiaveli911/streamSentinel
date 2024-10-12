FROM python:3.9-slim

WORKDIR /app

# Copie et installation des dépendances
COPY requirements.txt .

# Installer les dépendances

RUN pip install --no-cache-dir -r requirements.txt

# Copie du code source
COPY . .

RUN ls -al

# Lancer le script Python
ENTRYPOINT ["python", "streamSentinel.py"]