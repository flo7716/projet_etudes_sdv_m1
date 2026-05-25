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
echo -e "${RED}"
echo "     ____________________________"
echo " ___/  ________________________  \___"
echo "/  _   _   _   _   _   _   _   _   _  \ /"
echo "|_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_/ \_| /"
echo "     \__________________________/"
echo ""
echo "    PENTEST TOOLBOX - SWISSKNIFE CLI"
echo "    Security Testing Framework"
echo -e "${NC}"

# Check if API service is running
echo -e "${YELLOW}Checking Docker setup...${NC}"

# Build the Docker images api (and dvwa if requested by the user) if they don't exist, and start DVWA if it's not running
IMAGE_NAME="projet_etudes_sdv_m1-api"
DVWA_IMAGE_NAME="vulnerables/web-dvwa"
if ! docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^$IMAGE_NAME:"; then
    echo -e "${YELLOW}Building API Docker image...${NC}"
    docker build -t "$IMAGE_NAME" -f Dockerfile .
    echo -e "${GREEN}✓ API image built successfully${NC}"
else
    echo -e "${GREEN}✓ API image already exists${NC}"
fi

# Ask the user if they want to start DVWA
read -p "Do you want to start DVWA (Damn Vulnerable Web Application)? (y/n)  " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if ! docker images --format '{{.Repository}}:{{.Tag}}' | grep -q "^$DVWA_IMAGE_NAME:"; then
        echo -e "${YELLOW}Pulling DVWA Docker image...${NC}"
        docker pull "$DVWA_IMAGE_NAME"
        echo -e "${GREEN}✓ DVWA image pulled successfully${NC}"
        docker compose up -d dvwa
        echo -e "${GREEN}✓ DVWA service started${NC}"
        # Wait a few seconds for DVWA to start and then give the user the ip and port
        sleep 5
        # Get the DVWA container IP address
        DVWA_CONTAINER_ID=$(docker ps -qf "ancestor=$DVWA_IMAGE_NAME")
        if [ -n "$DVWA_CONTAINER_ID" ]; then
        echo -e "${YELLOW}DVWA is running at http://$DVWA_IP:80${NC}"
        echo -e "${YELLOW}Note: The above IP may not be accessible from your host if Docker uses a user-defined bridge network.${NC}"
        echo -e "${YELLOW}If you used the default docker-compose setup, access DVWA at http://localhost:8080${NC}"
            echo -e "${YELLOW}DVWA is running at http://$DVWA_IP:80${NC}"
        else
            echo -e "${RED}Error: DVWA container is not running.${NC}"
        fi
    else
        echo -e "${GREEN}✓ DVWA image already exists${NC}"
    fi
fi

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
