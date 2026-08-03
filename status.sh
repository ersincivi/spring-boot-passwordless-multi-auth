#!/bin/bash

# Service Status and Management Script
# Shows current status and provides management options

set -e

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}📊 Passwordless Multi-Auth App Service Status${NC}"
echo -e "${YELLOW}================================${NC}"

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ docker-compose is not available${NC}"
    exit 1
fi

echo -e "${BLUE}📋 Service Status:${NC}"
docker ps --filter "name=passwordless_" --format "table {{.Names}}\\t{{.Status}}\\t{{.Ports}}"

echo ""
echo -e "${BLUE}🔗 Available Access Points:${NC}"

# Check and display access points for running services
if docker ps --format "{{.Names}} {{.Status}}" | grep -q "passwordless_app .*Up"; then
    echo -e "${GREEN}✅ App: http://localhost:8585${NC}"
fi

if docker ps --format "{{.Names}} {{.Status}}" | grep -q "passwordless_kibana .*Up"; then
    echo -e "${GREEN}✅ Kibana: http://localhost:5601${NC}"
fi

if docker ps --format "{{.Names}} {{.Status}}" | grep -q "passwordless_grafana .*Up"; then
    echo -e "${GREEN}✅ Grafana: http://localhost:3000 (user: admin, password: GRAFANA_ADMIN_PASSWORD from .env)${NC}"
fi

if docker ps --format "{{.Names}} {{.Status}}" | grep -q "passwordless_prometheus .*Up"; then
    echo -e "${GREEN}✅ Prometheus: http://localhost:9090${NC}"
fi

if docker ps --format "{{.Names}} {{.Status}}" | grep -q "passwordless_elasticsearch .*Up"; then
    echo -e "${GREEN}✅ Elasticsearch: http://localhost:9200${NC}"
fi

if docker ps --format "{{.Names}} {{.Status}}" | grep -q "passwordless_pgadmin .*Up"; then
    echo -e "${GREEN}✅ PgAdmin: http://localhost:5050 (admin@example.com / PGADMIN_PASSWORD from .env)${NC}"
fi

if docker ps --format "{{.Names}} {{.Status}}" | grep -q "passwordless_mailpit .*Up"; then
    echo -e "${GREEN}✅ Mailpit: http://localhost:8025${NC}"
fi

if docker ps --format "{{.Names}} {{.Status}}" | grep -q "passwordless_elasticsearch_head .*Up"; then
    echo -e "${GREEN}✅ Elasticsearch Head: http://localhost:9101${NC}"
fi

echo ""
echo -e "${BLUE}🔧 Quick Management Commands:${NC}"
echo "   1. View service logs: docker-compose logs -f [service-name]"
echo "   2. Restart service: docker-compose restart [service-name]"
echo "   3. Stop service: docker-compose stop [service-name]"
echo "   4. Start service: docker-compose start [service-name]"
echo "   5. Scale service: docker-compose up -d --scale [service-name]=2"
echo ""
echo -e "${BLUE}📊 Resource Usage:${NC}"
if command -v docker &> /dev/null; then
    docker stats --no-stream --format "table {{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.NetIO}}" | head -10
fi

echo ""
echo -e "${BLUE}💾 Volume Usage:${NC}"
docker volume ls | grep passwordless || echo "No project volumes found"

echo ""
echo -e "${BLUE}🚀 Available Startup Scripts:${NC}"
echo "   • ./start-dev.sh - Start minimal dev stack (postgres, redis, mailpit)"
echo "   • ./start-prod.sh - Start production-profile stack"
echo "   • ./start-fullstack.sh - Start everything (app + ELK + monitoring)"
echo "   • ./stop.sh - Stop all services"