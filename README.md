# Projet Stage - ASM Pipeline

Ce projet est un outil de découverte et de scan (Attack Surface Management). 

## Lancement avec Docker (Recommandé)

Le projet est entièrement conteneurisé. En utilisant Docker Compose, vous n'avez plus besoin d'installer ou de lancer MongoDB manuellement sur votre machine.

### Prérequis
*   Docker et Docker Compose installés sur votre système.

### Démarrage
1.  Assurez-vous d'avoir configuré votre fichier `.env` à la racine du projet.
2.  Lancez la commande suivante à la racine :
    ```bash
    docker compose up --build
    ```

Cette commande va démarrer automatiquement :
*   Le conteneur MongoDB (`asm_mongodb`) avec persistance des données.
*   Le conteneur de l'application (`asm_app`) hébergeant l'API FastAPI sur le port `8000`.

L'API et l'interface Web du projet seront accessibles à l'adresse : [http://localhost:8000](http://localhost:8000).

---

## Lancement Local (Sans Docker)

### Prérequis

- Python 3.x
- MongoDB (installé localement)

### Démarrage de la base de données

Étant donné que MongoDB n'est pas configuré en tant que service Windows, **vous devez le démarrer manuellement avant d'exécuter le pipeline**. 

Un script a été préparé pour faciliter cette étape. Ouvrez un terminal PowerShell à la racine du projet et exécutez :

```powershell
powershell -ExecutionPolicy Bypass -File tools\start_mongo.ps1
```

Ce script va :
1. Vérifier si MongoDB tourne déjà.
2. Créer les dossiers de données (`C:\data\db`) s'ils n'existent pas.
3. Lancer `mongod.exe` en arrière-plan.

### Lancement du Pipeline ou de l'API

Une fois la base de données démarrée :

*   **Pour lancer l'API et l'interface Web :**
    ```bash
    python -m api.main
    ```

*   **Pour lancer un scan en ligne de commande :**
    ```bash
    python -m pipeline.runner <domaine>
    ```

    Exemple :
    ```bash
    python -m pipeline.runner example.com
    ```

