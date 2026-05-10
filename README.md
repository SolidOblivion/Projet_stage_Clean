# Projet Stage - ASM Pipeline

Ce projet est un outil de découverte et de scan (Attack Surface Management). 

## Prérequis

- Python 3.x
- MongoDB 7.0 (installé sans service)

## Démarrage de la base de données

Étant donné que MongoDB n'est pas configuré en tant que service Windows, **vous devez le démarrer manuellement avant d'exécuter le pipeline**. 

Un script a été préparé pour faciliter cette étape. Ouvrez un terminal PowerShell à la racine du projet et exécutez :

```powershell
powershell -ExecutionPolicy Bypass -File tools\start_mongo.ps1
```

Ce script va :
1. Vérifier si MongoDB tourne déjà.
2. Créer les dossiers de données (`C:\data\db`) s'ils n'existent pas.
3. Lancer `mongod.exe` en arrière-plan.

## Lancement du Pipeline

Une fois la base de données démarrée, vous pouvez lancer un scan :

```bash
python -m pipeline.runner <domaine>
```

Exemple :
```bash
python -m pipeline.runner example.com
```
