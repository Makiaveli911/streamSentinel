from plexapi.server import PlexServer
from plexapi.myplex import MyPlexAccount
from dotenv import load_dotenv

import sqlite3
import logging
import time
import os

# Configurer le module logging
logging.basicConfig(
    level=logging.INFO,  # Choix du niveau de logging (peut être changé à DEBUG pour plus de détails)
    format='%(asctime)s - %(levelname)s - %(message)s',  # Format des messages de log
    handlers=[logging.StreamHandler()]  # Permet de voir les logs dans la console Docker
)

# Charger les variables à partir du fichier .env
load_dotenv()

# Charger la whitelist depuis le fichier .env
PLEX_TOKEN = os.getenv('PLEX_TOKEN')
PLEX_URL = os.getenv('PLEX_URL')
EMAIL = os.getenv('EMAIL')
MOT_DE_PASS = os.getenv('MOT_DE_PASS')
WHITELIST_USERS = os.getenv('WHITELIST_USERS', '')  # Récupérer les utilisateurs whitelist
whitelist = WHITELIST_USERS.split(',')  # Transformer la chaîne en une liste
TIME_RESTART = int(os.getenv('TIME_RESTART')) #Convertir car c'est un integer pas un string 

# Vérifier si les variables sont correctement chargées
if not PLEX_TOKEN or not PLEX_URL:
    raise ValueError("Les variables PLEX_TOKEN et PLEX_URL doivent être définies dans le fichier .env")

# Configuration
MAX_WARNINGS = 3

# Initialisation de la connexion Plex
logging.info("Connexion à Plex Server...")
plex = PlexServer(PLEX_URL, PLEX_TOKEN)
account = MyPlexAccount(EMAIL, MOT_DE_PASS)

# Connexion à la base de données SQLite
conn = sqlite3.connect('streamSentinel.db')
c = conn.cursor()

# Créer la table des avertissements si elle n'existe pas
c.execute('''CREATE TABLE IF NOT EXISTS warnings (
                user TEXT PRIMARY KEY,
                count INTEGER
             )''')
conn.commit()

# Dictionnaire pour stocker les avertissements par utilisateur
warnings = {}

# Fonction pour ajouter un log dans un fichier texte
def log_to_file(user, ips, warning_count):
    warning_date = time.strftime('%Y-%m-%d %H:%M:%S')  # Date et heure actuelle
    log_message = f"Utilisateur: {user}, IPs: {', '.join(ips)}, Avertissements: {warning_count}/3, Date: {warning_date}\n"
    
    # Ouvre le fichier en mode append pour ajouter les logs à la fin du fichier
    with open('streamSentinel_warnings.log', 'a') as log_file:
        log_file.write(log_message)
    
    logging.info(f"Log écrit dans le fichier pour {user} : {log_message.strip()}")

# Fonction pour obtenir le nombre d'avertissements d'un utilisateur
def get_warning_count(user):
    c.execute('SELECT count FROM warnings WHERE user = ?', (user,))
    result = c.fetchone()
    if result:
        return result[0]
    else:
        return 0

# Fonction pour mettre à jour le nombre d'avertissements
def update_warning_count(user, count):
    if get_warning_count(user) == 0:
        c.execute('INSERT INTO warnings (user, count) VALUES (?, ?)', (user, count))
    else:
        c.execute('UPDATE warnings SET count = ? WHERE user = ?', (count, user))
    conn.commit()

# Fonction pour réinitialiser les avertissements
def reset_warning_count(user):
    c.execute('DELETE FROM warnings WHERE user = ?', (user,))
    conn.commit()

# Fonction pour vérifier si un utilisateur est dans la whitelist
def is_in_whitelist(user):
    return user in whitelist

# Fonction pour révoquer les accès aux bibliothèques d'un utilisateur sans le supprimer de la liste d'amis
def revoke_access(user_name):
    try:
        user_to_revoke = None
        for user in account.users():
            if user.username == user_name:
                user_to_revoke = user
                break

        if user_to_revoke:
            account.removeFriend(user_to_revoke)
            logging.info(f"Accès à toutes les bibliothèques révoqués pour {user_to_revoke.username}.")
        else:
            logging.warning(f"Utilisateur {user_name} non trouvé.")
    except Exception as e:
        logging.error(f"Erreur lors de la révocation des accès aux bibliothèques : {e}")

# Fonction pour vérifier les sessions en cours
def check_sessions():
    active_sessions = plex.sessions()
    user_ips = {}

    # Fermer toutes les sessions en pause
    for session in active_sessions:
        # Vérifier si le player a un état
        if session.players:
            for player in session.players:
                if hasattr(player, 'state'):
                    logging.info(f"État du lecteur : {player.state} pour l'utilisateur {session.usernames[0]}")
                    if player.state == 'paused':
                        logging.info(f"Fermeture de la session en pause pour {session.usernames[0]} avec sessionKey : {session.sessionKey}")
                        session.stop(reason='Session en pause fermée automatiquement')
                else:
                    logging.warning(f"Le lecteur de la session {session.sessionKey} n'a pas d'attribut 'state'.")
    
    time.sleep(10)  # Pause de 10 secondes

    # Mise à jour des sessions après avoir fermé les sessions en pause
    active_sessions = plex.sessions()

    # Collecte des IPs pour chaque utilisateur
    for session in active_sessions:
        user = session.usernames[0]  # Nom d'utilisateur
        if is_in_whitelist(user):
            logging.info(f"{user} est dans la whitelist, exclusion des contrôles IP.")
            continue  # Passer au suivant sans faire de contrôle
        ip = session.players[0].address  # Adresse IP du lecteur
        session_key = session.sessionKey  # Clé de session

        logging.info(f"Session trouvée : {user}, IP : {ip}, sessionKey : {session_key}")

        # Regroupement des IPs par utilisateur
        if user not in user_ips:
            user_ips[user] = []
        user_ips[user].append(ip)

    # Vérification des utilisateurs avec plusieurs IPs
    for user, ips in user_ips.items():
        unique_ips = set(ips)
        logging.info(f"Utilisateur : {user}, IPs : {unique_ips}")

        if len(unique_ips) > 1:
            logging.warning(f"Alerte! {user} utilise plusieurs IPs : {unique_ips}")
            if user not in warnings:
                # Charger le compteur depuis la base de données
                warnings[user] = get_warning_count(user) 
            warnings[user] += 1
            # Mettre à jour la base de données
            update_warning_count(user, warnings[user])

            # Enregistrer le log dans le fichier texte
            log_to_file(user, unique_ips, warnings[user])

            # Gestion des avertissements
            if warnings[user] >= MAX_WARNINGS:
                logging.error(f"Utilisateur {user} a dépassé le nombre d'avertissements.")
                stop_sessions(user, active_sessions, f"""Bonjour {user},

                🎬 Breaking News 🎬
                
                Il semble que vous ayez battu un record impressionnant... celui de regarder plusieurs contenus depuis des IPs différentes en même temps ! 😲 
                Malheureusement, ici, on est plutôt dans l’esprit "un pour tous, et tous pour un" plutôt que "un compte pour tout le quartier". 😅

                Alors, avant que vous ne transformiez votre salon en multiplex, nous sommes dans l'obligation de vous *bannir* de nos bibliothèques pour "non-respect des règles de partage". 

                💥 Game Over 💥
                Votre session va être arrêtée dans quelques instants... mais ne vous inquiétez pas, vous pouvez toujours lire ce message avec un sourire (avant que tout ne s’arrête). 😉

                Merci de votre compréhension et bonne chance dans votre quête d'un autre compte Plex !

                Cordialement,
                Le Grand Gardien des Bibliothèques Plex 📽️""")
                # Ajout d'un délai pour s'assurer que le message est envoyé
                time.sleep(10)  # Pause de 5 secondes
                revoke_access(user)  # Révoquer les accès aux bibliothèques sans supprimer des amis
                reset_warning_count(user)  # Réinitialiser les avertissements dans la base de données
                warnings[user] = 0
            elif warnings [user] == 1:
                stop_sessions(user, active_sessions, f"""Bonjour {user},

                Nous avons détecté une activité inhabituelle sur votre compte Plex. Il semble que plusieurs appareils utilisant des adresses IP différentes soient actuellement connectés et visionnent des contenus simultanément.

                Pour rappel, l'utilisation du même compte sur des IPs multiples peut enfreindre nos règles de partage. Nous vous demandons de limiter l'utilisation à un seul réseau IP à la fois. Si cette situation persiste, des actions supplémentaires pourraient être prises, y compris la suspension de votre accès.

                Merci de votre compréhension,
                Le Bot de Surveillance Plex.
                """)
            else:
                # Arrêter les sessions en cours
                stop_sessions(user, active_sessions, f"""Bonjour {user},
                
                Ceci est votre **DEUXIEME AVERTISSEMENT AVANT SANCTION** concernant l'utilisation de plusieurs adresses IP simultanément sur votre compte Plex.

                Nous avons détecté plusieurs connexions provenant d'IP différentes, ce qui enfreint nos règles d'utilisation du partage de compte. Si cette activité continue, votre accès à Plex pourra être suspendu après un autre avertissement.

                Merci de prendre des mesures pour vous conformer aux règles d'utilisation.

                Cordialement,
                Le Bot de Surveillance Plex.
                """)

# Fonction pour stopper les sessions d'un utilisateur
def stop_sessions(user, active_sessions,reason_message):
    for session in active_sessions:
        if session.usernames[0] == user:
           try:
                # Vérifier que la session a un ID valide
                if session.session and hasattr(session.session, 'id'):
                    logging.info(f"Arrêt de la session de {user} avec sessionKey : {session.sessionKey}")
                    session.stop(reason=reason_message)
                else:
                    logging.warning(f"Session {session.sessionKey} n'a pas de session ID valide.")    
           except AttributeError as e:
                logging.error(f"Erreur lors de l'arrêt de la session : {e}")
        else:
            print(f"Impossible d'arrêter la session de {user} car elle n'a pas de sessionKey ou de players valide.")

# Fonction pour afficher le temps d'attente en format lisible (minutes, heures ou secondes)
def format_time_interval(seconds):
    if seconds < 60:
        return f"{seconds} secondes"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    else:
        hours = seconds / 3600
        return f"{hours:.1f} heures"

# Boucle principale du streamSentinel
def run_streamSentinel():
    while True:
        logging.info("-------- Démarrage d'une nouvelle vérification --------")
        check_sessions()

        # Conversion de TIME_RESTART en format lisible
        formatted_time = format_time_interval(TIME_RESTART)
        logging.info("Attente avant la prochaine vérification ({formatted_time})...")
        time.sleep(TIME_RESTART)

# Démarrage du streamSentinel
if __name__ == '__main__':
    run_streamSentinel()
