#!/bin/bash

# Stop the running API service and cleanup
# Use this when you're done with the interactive CLI

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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

echo -e "${CYAN}Stopping API service...${NC}"

# Stop and remove the containers
if $DOCKER_CMD ps | grep -q "$(basename "$(pwd)")_api"; then
    echo -e "${YELLOW}Stopping running containers...${NC}"
    $DOCKER_CMD down
    echo -e "${GREEN}✓ Services stopped${NC}"
else
    echo -e "${YELLOW}No running services found${NC}"
fi

echo -e "${GREEN}Cleanup complete${NC}"
