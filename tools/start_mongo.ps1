# ============================================================
#  Script de démarrage de MongoDB 7.0
# ============================================================
#  MongoDB n'est PAS installé comme service Windows.
#  Exécutez ce script AVANT de lancer le pipeline :
#
#    powershell -ExecutionPolicy Bypass -File tools\start_mongo.ps1
#
# ============================================================

$mongodPath = "C:\Program Files\MongoDB\Server\7.0\bin\mongod.exe"
$dataPath   = "C:\data\db"
$port       = 27017

# --- Vérifier si mongod tourne déjà ---
$existing = Get-Process -Name "mongod" -ErrorAction SilentlyContinue
if ($existing) {
    $listening = netstat -ano | Select-String ":$port.*LISTENING"
    if ($listening) {
        Write-Host "[OK] MongoDB tourne deja (PID $($existing.Id), port $port)" -ForegroundColor Green
        exit 0
    }
}

# --- Vérifier que le binaire existe ---
if (-not (Test-Path $mongodPath)) {
    Write-Host "[ERREUR] mongod.exe introuvable : $mongodPath" -ForegroundColor Red
    exit 1
}

# --- Créer le dossier de données si nécessaire ---
if (-not (Test-Path $dataPath)) {
    New-Item -ItemType Directory -Force -Path $dataPath | Out-Null
    Write-Host "[INFO] Dossier de donnees cree : $dataPath"
}

# --- Lancer mongod en arrière-plan ---
Write-Host "[INFO] Demarrage de MongoDB 7.0 sur le port $port..."
Start-Process -FilePath $mongodPath `
    -ArgumentList "--dbpath", $dataPath, "--port", $port, "--bind_ip", "127.0.0.1" `
    -WindowStyle Minimized

# --- Attendre que le port soit ouvert ---
$timeout = 10
for ($i = 0; $i -lt $timeout; $i++) {
    Start-Sleep 1
    $listening = netstat -ano | Select-String ":$port.*LISTENING"
    if ($listening) {
        $proc = Get-Process -Name "mongod" -ErrorAction SilentlyContinue
        Write-Host "[OK] MongoDB demarre avec succes (PID $($proc.Id), port $port)" -ForegroundColor Green
        exit 0
    }
}

Write-Host "[ERREUR] MongoDB n'a pas demarre dans les $timeout secondes" -ForegroundColor Red
exit 1
