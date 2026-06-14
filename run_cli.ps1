# Pentest Toolbox - Interactive CLI Launcher (Windows)
# Run with: powershell -ExecutionPolicy Bypass -File run_cli.ps1

$ErrorActionPreference = "Stop"

function Write-Color($msg, $color) { Write-Host $msg -ForegroundColor $color }

# Check project root
if (-not (Test-Path "docker-compose.yml")) {
    Write-Color "Error: docker-compose.yml not found. Please run this script from the project root directory." Red
    exit 1
}

Write-Color "Checking Docker setup..." Yellow

$IMAGE_NAME      = "projet_etudes_sdv_m1-api"
$DVWA_IMAGE_NAME = "vulnerables/web-dvwa"

# Build API image if missing
$existingApi = docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -match "^${IMAGE_NAME}:" }
if (-not $existingApi) {
    Write-Color "Building API Docker image..." Yellow
    docker build -t $IMAGE_NAME -f Dockerfile .
    Write-Color "OK - API image built successfully" Green
} else {
    Write-Color "OK - API image already exists" Green
}

Clear-Host

# Ask about DVWA
$reply = Read-Host "Do you want to start DVWA (Damn Vulnerable Web Application)? (y/n)"
if ($reply -match "^[Yy]$") {
    $existingDvwa = docker images --format "{{.Repository}}:{{.Tag}}" | Where-Object { $_ -match "^${DVWA_IMAGE_NAME}:" }
    if (-not $existingDvwa) {
        Write-Color "Pulling DVWA Docker image..." Yellow
        docker pull $DVWA_IMAGE_NAME
        Write-Color "OK - DVWA image pulled successfully" Green
        docker compose up -d dvwa
        Write-Color "OK - DVWA service started" Green

        Start-Sleep -Seconds 5

        $dvwaContainerId = docker ps -qf "ancestor=$DVWA_IMAGE_NAME"
        if ($dvwaContainerId) {
            $dvwaIp = docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $dvwaContainerId
            Write-Color "DVWA is running at https://${dvwaIp}:443" Yellow
            Write-Color "From your host, use https://localhost:8443" Yellow
            Write-Color "The HTTP port 8080 is still available for compatibility." Yellow
        } else {
            Write-Color "Error: DVWA container is not running." Red
        }
    } else {
        Write-Color "OK - DVWA image already exists" Green
    }
}

Write-Color "Launching interactive CLI..." Green

# Banner - written as individual Write-Host calls to avoid here-string pipe issues
Write-Host ""
Write-Host "     ____________________________" -ForegroundColor Red
Write-Host " ___/  ________________________  \___" -ForegroundColor Red
Write-Host "/  _   _   _   _   _   _   _   _   _  \ /" -ForegroundColor Red
Write-Host "    \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_| /" -ForegroundColor Red
Write-Host "     \__________________________/" -ForegroundColor Red
Write-Host ""
Write-Host "    PENTEST TOOLBOX - SWISSKNIFE CLI" -ForegroundColor Red
Write-Host "    Security Testing Framework" -ForegroundColor Red
Write-Host ""

# Convert Windows path to Unix-style for Docker volume mount
$currentPath = (Get-Location).Path
$pwd_unix = $currentPath -replace '\\', '/' -replace '^([A-Za-z]):', '/$1'
$volumeArg = "${pwd_unix}:/app"

docker compose run -it --rm `
    -v $volumeArg `
    -w /app `
    $IMAGE_NAME `
    python3 -m app.cli_interactive

$exit_code = $LASTEXITCODE
if ($exit_code -eq 0) {
    Write-Color "OK - CLI session ended successfully" Green
} else {
    Write-Color "FAILED - CLI session ended with error code: $exit_code" Red
}

exit $exit_code