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

# Build the Docker image if needed
IMAGE_NAME="projet_etudes_sdv_m1-api"
if ! docker images | grep -q "$IMAGE_NAME"; then
    echo -e "${YELLOW}Building Docker image...${NC}"
    docker build -t "$IMAGE_NAME" .
fi

# Run the interactive CLI directly in a Docker container
echo -e "${GREEN}Launching interactive CLI...${NC}"
docker run -it --rm \
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
