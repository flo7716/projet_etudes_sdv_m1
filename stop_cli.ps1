# Pentest Toolbox - Interactive CLI Launcher (Windows)
# Run with: powershell -ExecutionPolicy Bypass -File stop_cli.ps1

$ErrorActionPreference = "Stop"

function Write-Color($msg, $color) { Write-Host $msg -ForegroundColor $color }

# Check project root
if (-not (Test-Path "docker-compose.yml")) {
    Write-Color "Error: docker-compose.yml not found. Please run this script from the project root directory." Red
    exit 1
}

# Stop DVWA service if running
$dvwaContainerId = docker ps -qf "ancestor=vulnerables/web-dvwa"
if ($dvwaContainerId) {
    Write-Color "Stopping DVWA service..." Yellow
    docker compose stop dvwa
    Write-Color "OK - DVWA service stopped" Green
} else {
    Write-Color "DVWA service is not running." Yellow
}

# Stop API service if running
$apiContainerId = docker ps -qf "ancestor=projet_etudes_sdv_m1-api"
if ($apiContainerId) {
    Write-Color "Stopping API service..." Yellow
    docker compose stop api
    Write-Color "OK - API service stopped" Green
} else {
    Write-Color "API service is not running." Yellow
}   


# Stop all other services defined in docker-compose.yml
Write-Color "Stopping all other services..." Yellow
docker compose stop
Write-Color "OK - All services stopped" Green