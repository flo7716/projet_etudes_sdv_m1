#!/bin/bash

# Pentest Toolbox - Interactive CLI Launcher
# This script provides an easy way to run the interactive CLI interface

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color


# Check if we're in the project root directory (where docker-compose.yml is located)
if [ ! -f "docker-compose.yml" ]; then
    echo -e "${RED}Error: docker-compose.yml not found. Please run this script from the project root directory.${NC}"
    exit 1
fi

# Display banner
echo -e "${CYAN}"
echo "╔════════════════════════════════════════╗"
echo "║    PENTEST TOOLBOX - Interactive CLI   ║"
echo "║     Security Testing Framework         ║"
echo "╚════════════════════════════════════════╝"
echo -e "${NC}"

# Check if API service is running
echo -e "${YELLOW}Checking Docker setup...${NC}"

# Build the Docker images (api and dvwa) if needed
IMAGE_NAME="projet_etudes_sdv_m1-api"
DVWA_IMAGE_NAME="vulnerables/web-dvwa"
if [[ "$(docker images -q $IMAGE_NAME 2> /dev/null)" == "" ]]; then
    echo -e "${YELLOW}Building API Docker image...${NC}"
    docker compose build
else
    echo -e "${GREEN}✓ API Docker image already exists.${NC}"
fi

if [[ "$(docker images -q $DVWA_IMAGE_NAME 2> /dev/null)" == "" ]]; then
    echo -e "${YELLOW}Pulling DVWA Docker image...${NC}"
    docker pull $DVWA_IMAGE_NAME
else
    echo -e "${GREEN}✓ DVWA Docker image already exists.${NC}"
fi

# Start DVWA if not running
DVWA_CONTAINER=$(docker compose ps -q dvwa)

if [ -z "$DVWA_CONTAINER" ]; then
    echo -e "${YELLOW}Starting DVWA container...${NC}"
    docker compose up -d dvwa
else
    DVWA_STATUS=$(docker inspect -f '{{.State.Running}}' "$DVWA_CONTAINER")

    if [ "$DVWA_STATUS" != "true" ]; then
        echo -e "${YELLOW}Starting existing DVWA container...${NC}"
        docker compose start dvwa
    else
        echo -e "${GREEN}✓ DVWA container is already running.${NC}"
    fi
fi

# Get the DVWA ip address from the docker-compose setup
DVWA_IP=$(docker compose ps -q dvwa | xargs docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
if [ -z "$DVWA_IP" ]; then
    echo -e "${RED}Error: Could not find DVWA container. Please ensure it is running.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker setup looks good. For testing, you can use the DVWA IP: ${DVWA_IP}${NC}"

# Run the interactive CLI directly in a Docker container
echo -e "${GREEN}Launching interactive CLI...${NC}"
docker compose run -it --rm \
    -v "$(pwd)":/app \
    -w /app \
    "$IMAGE_NAME" \
    python3 -m app.cli_interactive

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo -e "${GREEN}✓ CLI session ended successfully${NC}"
else
    echo -e "${RED}✗ CLI session ended with error code: $exit_code${NC}"
fi

exit $exit_code
