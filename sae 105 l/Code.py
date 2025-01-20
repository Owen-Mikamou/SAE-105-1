# Importation des bibliothèques nécessaires
import csv  # Pour manipuler des fichiers CSV
import matplotlib.pyplot as plt  # Pour créer des graphiques

# ## Ouverture du fichier "DumpFile.txt"
fichier = open("DumpFile.txt", "r")  # Ouvre le fichier contenant les données réseau

# ## Création des listes pour stocker les données extraites
ipsr = []  # Liste pour les adresses IP source
ipde = []  # Liste pour les adresses IP destination
longueur = []  # Liste pour les longueurs des paquets
flag = []  # Liste pour les flags des paquets
seq = []  # Liste pour les numéros de séquence
heure = []  # Liste pour les heures des paquets

# ## Initialisation des compteurs pour les statistiques
flagcounterP = 0  # Compteur pour les flags [P.]
flagcounterS = 0  # Compteur pour les flags [S]
flagcounter = 0  # Compteur pour les flags [.]
framecounter = 0  # Compteur pour le nombre total de trames
requestcounter = 0  # Compteur pour les requêtes ICMP
replycounter = 0  # Compteur pour les réponses ICMP
seqcounter = 0  # Compteur pour les numéros de séquence
ackcounter = 0  # Compteur pour les accusés de réception (ACK)
wincounter = 0  # Compteur pour les fenêtres (WIN)

# ## Analyse du fichier ligne par ligne
for ligne in fichier:  # Parcourt chaque ligne du fichier
    split = ligne.split(" ")  # Sépare la ligne en une liste de mots
    if "IP" in ligne:  # Vérifie si la ligne contient des données IP
        framecounter += 1  # Incrémente le compteur de trames
        if "[P.]" in ligne:  # Vérifie si le flag [P.] est présent
            flag.append("[P.]")  # Ajoute le flag [P.] à la liste
            flagcounterP += 1  # Incrémente le compteur de flags [P.]
        if "[.]" in ligne:  # Vérifie si le flag [.] est présent
            flag.append("[.]")  # Ajoute le flag [.] à la liste
            flagcounter += 1  # Incrémente le compteur de flags [.]
        if "[S]" in ligne:  # Vérifie si le flag [S] est présent
            flag.append("[S]")  # Ajoute le flag [S] à la liste
            flagcounterS += 1  # Incrémente le compteur de flags [S]
        if "seq" in ligne:  # Vérifie si la ligne contient un numéro de séquence
            seqcounter += 1  # Incrémente le compteur de séquences
            seq.append(split[8])  # Ajoute le numéro de séquence à la liste
        if "win" in ligne:  # Vérifie si la ligne contient une fenêtre (WIN)
            wincounter += 1  # Incrémente le compteur de fenêtres
        if "ack" in ligne:  # Vérifie si la ligne contient un accusé de réception (ACK)
            ackcounter += 1  # Incrémente le compteur d'ACK
        ipsr.append(split[2])  # Ajoute l'adresse IP source à la liste
        ipde.append(split[4])  # Ajoute l'adresse IP destination à la liste
        heure.append(split[0])  # Ajoute l'heure du paquet à la liste
        if "length" in ligne:  # Vérifie si la ligne contient une longueur de paquet
            split = ligne.split(" ")  # Sépare la ligne en une liste de mots
            if "HTTP" in ligne:  # Vérifie si le paquet est HTTP
                longueur.append(split[-2])  # Ajoute la longueur du paquet HTTP à la liste
            else:
                longueur.append(split[-1])  # Ajoute la longueur du paquet à la liste
        if "ICMP" in ligne:  # Vérifie si la ligne contient des données ICMP
            if "request" in ligne:  # Vérifie si c'est une requête ICMP
                requestcounter += 1  # Incrémente le compteur de requêtes ICMP
            if "reply" in ligne:  # Vérifie si c'est une réponse ICMP
                replycounter += 1  # Incrémente le compteur de réponses ICMP

# ## Calcul des pourcentages pour les graphiques
globalflagcounter = flagcounter + flagcounterP + flagcounterS  # Total des flags
P = flagcounterP / globalflagcounter  # Pourcentage de flags [P.]
S = flagcounterS / globalflagcounter  # Pourcentage de flags [S]
A = flagcounter / globalflagcounter  # Pourcentage de flags [.]

globalreqrepcounter = replycounter + requestcounter  # Total des requêtes et réponses ICMP
req = requestcounter / globalreqrepcounter  # Pourcentage de requêtes ICMP
rep = replycounter / globalreqrepcounter  # Pourcentage de réponses ICMP

# ## Création des graphiques avec matplotlib
# ### Diagramme circulaire pour les flags
name = ['Flag [.]', 'Flag [P]', 'Flag [S]']  # Étiquettes pour le graphique
data = [A, P, S]  # Données pour le graphique
explode = (0, 0, 0)  # Configuration pour le diagramme circulaire
plt.pie(data, explode=explode, labels=name, autopct='%1.1f%%', startangle=90, shadow=True)  # Crée le diagramme circulaire
plt.axis('equal')  # Assure que le diagramme est circulaire
plt.savefig("graphe1.png")  # Sauvegarde le graphique en fichier PNG
plt.show()  # Affiche le graphique

# ### Diagramme circulaire pour les requêtes et réponses ICMP
name2 = ['Request', 'Reply']  # Étiquettes pour le graphique
data2 = [req, rep]  # Données pour le graphique
explode = (0, 0)  # Configuration pour le diagramme circulaire
plt.pie(data2, explode=explode, labels=name2, autopct='%1.1f%%', startangle=90, shadow=True)  # Crée le diagramme circulaire
plt.savefig("graphe2.png")  # Sauvegarde le graphique en fichier PNG
plt.show()  # Affiche le graphique

# ### Diagramme en barres pour les séquences, accusés de réception et fenêtres
labels = ['Sequences', 'Acknowledgements', 'Windows']  # Étiquettes pour le graphique
values = [seqcounter, ackcounter, wincounter]  # Données pour le graphique
plt.bar(labels, values, color=['blue', 'green', 'red'])  # Crée le diagramme en barres
plt.title('Statistiques des séquences, accusés de réception et fenêtres')  # Titre du graphique
plt.ylabel('Nombre')  # Étiquette de l'axe Y
plt.savefig("graphe3.png")  # Sauvegarde le graphique en fichier PNG
plt.show()  # Affiche le graphique

# ## Détection des attaques
detected_attacks = False  # Par défaut, aucune attaque n'est détectée

# Vérification des conditions pour détecter des attaques
if flagcounterS > 0 or requestcounter > 0 or replycounter > 0 or seqcounter > 0 or ackcounter > 0 or wincounter > 0:
    detected_attacks = True  # Si l'une de ces conditions est vraie, une attaque est détectée

# ## Création du contenu de la page web avec une condition
if detected_attacks:
    interpretation = '''
    <h3>Interprétation des résultats</h3>
    <p><strong>DNS NXDomain:</strong> Un nombre élevé de paquets DNS avec des erreurs NXDomain peut indiquer une attaque par déni de service (DoS) ciblant le serveur DNS ou des tentatives de résolution de noms de domaine inexistants.</p>
    <p><strong>Suspicious SYN:</strong> Un nombre élevé de paquets SYN sans les paquets correspondants (SYN-ACK) peut indiquer une attaque par SYN flood, qui est une forme de DoS visant à épuiser les ressources du serveur en envoyant de nombreuses requêtes de connexion incomplètes.</p>
    <p><strong>Repeated Payload:</strong> La présence de paquets avec des charges utiles répétées peut indiquer une tentative de contournement de la détection d'intrusion ou une attaque par injection de paquets.</p>
    <p>L’analyse de ces données m’a permis de savoir qu’il s’agit d’une attaque DDoS car d'une part il y a non seulement une récurrence de demandes de connexion avec la même adresse source et au même moment, d'autre part nous sommes également censés être sur un réseau local où l'on n’a pas besoin de se connecter à distance, mais ici nous observons une demande de connexion à distance avec SSH, ce qui prouve qu’il s’agit d’un intrus.</p>
    '''
else:
    interpretation = '''
    <h3>Interprétation des résultats</h3>
    <p>Aucune attaque ou anomalie suspecte n'a été détectée dans le fichier analysé.</p>
    '''

# ## Intégration de l'interprétation dans le contenu HTML
# ## Intégration de l'interprétation dans le contenu HTML
htmlcontenu = f'''
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="utf-8">
    <title>Traitement des données</title>
    <style>
        body {{
            background-image: url('istockphoto-1412282189-612x612.jpg');
            background-repeat: no-repeat;
            background-size: cover;
            color: white;
            background-attachment: fixed;
            margin: 0;
            padding: 0;
        }}
        center {{
            margin-top: 20px;
        }}
        .interpretation {{
            background-color: rgba(0, 0, 0, 0.7); /* Fond semi-transparent pour améliorer la lisibilité */
            padding: 20px;
            border-radius: 10px;
            margin: 20px auto;
            max-width: 800px;
        }}
    </style>
</head>
<body>
    <center>
        <h1>MIKAMOU MAYELE OWEN Willifried</h1>
        <h2>Projet SAE 15 groupe B1</h2>
        <p>Bienvenu sur la page web du traitement des données. <br> Je vais vous présenter les informations et données pertinentes que j'ai trouvées dans le fichier à traiter.</p>
        <h3>Nombre total des trames échangées</h3>
        <p>{framecounter}</p>
        <br>
        <h3>Drapeaux (Flags)</h3>
        <p>Nombre de flags [P] (PUSH) = {flagcounterP}</p>
        <p>Nombre de flags [S] (SYN) = {flagcounterS}</p>
        <p>Nombre de flags [.] (ACK) = {flagcounter}</p>
        <br>
        <img src="graphe1.png" alt="Graphique des flags">
        <h3>Nombre des requests et replies</h3>
        <p>Request = {requestcounter}</p>
        <p>Reply = {replycounter}</p>
        <br>
        <img src="graphe2.png" alt="Graphique des requêtes et réponses">
        <h3>Statistiques entre seq, windows et ack</h3>
        <p>Nombre de seq = {seqcounter}</p>
        <p>Nombre de win = {wincounter}</p>
        <p>Nombre de ack = {ackcounter}</p>
        <br>
        <img src="graphe3.png" alt="Graphique des séquences, accusés de réception et fenêtres">
    </center>

    <div class="interpretation">
        {interpretation}  <!-- Intégration de l'interprétation conditionnelle -->
    </div>
</body>
</html>
'''

# ## Création de la page web avec les informations et les graphiques
with open("mikamou_owen_willifried.html", "w", encoding='utf-8') as html:  # Ouvre un fichier HTML en mode écriture
    html.write(htmlcontenu)  # Écrit le contenu HTML dans le fichier
    print("Page web créée avec succès")  # Affiche un message de confirmation

# ## Fermeture du fichier texte
fichier.close()  # Ferme le fichier texte après lecture


# ## Création de la page web avec les informations et les graphiques
with open("mikamou_owen_willifried.html", "w", encoding='utf-8') as html:  # Ouvre un fichier HTML en mode écriture
    html.write(htmlcontenu)  # Écrit le contenu HTML dans le fichier
    print("Page web créée avec succès")  # Affiche un message de confirmation

# ## Fermeture du fichier texte
fichier.close()  # Ferme le fichier texte après lecture