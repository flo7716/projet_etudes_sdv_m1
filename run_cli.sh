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

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Error: Docker is not installed${NC}"
        exit 1
    fi
    # Try using 'docker compose' if 'docker-compose' is not available
    DOCKER_CMD="docker compose"
else
    DOCKER_CMD="docker-compose"
fi

# Check if the docker-compose has been built, if not, build it first
if ! $DOCKER_CMD images | grep -q "$(basename "$(pwd)")_api"; then
    echo -e "${YELLOW}Docker images not found. Building the project...${NC}"
    $DOCKER_CMD build
    $DOCKER_CMD up -d
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

# Build and run the interactive CLI
echo -e "${GREEN}Launching interactive CLI...${NC}"
$DOCKER_CMD run -it --rm \
    -v "$(pwd)":/app \
    --name pentest-cli \
    $(basename "$(pwd)")_api \
    python -m app.cli_interactive

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo -e "${GREEN}✓ CLI session ended successfully${NC}"
else
    echo -e "${RED}✗ CLI session ended with error code: $exit_code${NC}"
fi

exit $exit_code
