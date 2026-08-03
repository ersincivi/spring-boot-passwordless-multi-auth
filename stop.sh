#!/bin/bash

# Stop All Services Script
# Safely stops all running services and cleans up resources

set -e

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🛑 Stopping All Passwordless Multi-Auth Services${NC}"
echo -e "${YELLOW}========================${NC}"

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ docker-compose is not available${NC}"
    exit 1
fi

echo -e "${BLUE}📋 Current running services:${NC}"
docker-compose ps

echo ""
read -p "Do you want to stop all services? (y/N): " confirm

if [[ $confirm =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}🛑 Stopping all services...${NC}"
    docker-compose down
    
    echo ""
    read -p "Do you want to remove volumes (WARNING: This will delete all data)? (y/N): " remove_volumes
    
    if [[ $remove_volumes =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}⚠️  Removing volumes and data...${NC}"
        docker-compose down -v
        echo -e "${RED}🗑️  All data has been removed!${NC}"
    fi
    
    echo -e "${GREEN}✅ All services stopped${NC}"
else
    echo -e "${YELLOW}❌ Operation cancelled${NC}"
fi

echo ""
echo -e "${BLUE}🔧 Individual service management:${NC}"
echo "   • Stop specific service: docker-compose stop [service-name]"
echo "   • Start specific service: docker-compose start [service-name]"
echo "   • Restart specific service: docker-compose restart [service-name]"
echo "   • View logs: docker-compose logs [service-name]"