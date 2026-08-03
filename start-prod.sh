#!/bin/bash

# Start Secure App - Setup
# Only starts the core services needed for the application to work

set -e

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}🚀 Starting Passwordless Multi-Auth App - Setup${NC}"
echo -e "${YELLOW}======================================${NC}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start 🐳 Docker and try again."
    exit 1
fi

echo -e "${GREEN}✅ Docker and docker-compose are available ${NC}"
echo -e "${BLUE}📦 Starting core infrastructure services...${NC}"

# Start database and dependencies first
echo "Starting PostgreSQL database..."
docker-compose up -d postgres

echo "Starting Redis cache..."
docker-compose up -d redis

echo "Starting Mailpit email service..."
docker-compose up -d mailpit

echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"
sleep 15

# Check if PostgreSQL is ready
echo "Checking PostgreSQL connection..."
timeout=60
counter=0
while ! docker-compose exec postgres pg_isready -U secure > /dev/null 2>&1; do
    sleep 2
    counter=$((counter + 2))
    if [ $counter -ge $timeout ]; then
        echo "❌ PostgreSQL failed to start within $timeout seconds"
        exit 1
    fi
    printf "   PostgreSQL... (%ds/%ds)\\r" $counter $timeout
done

echo -e "${GREEN}✅ PostgreSQL is ready                    ${NC}"

# Start PgAdmin for database management
echo -e "${BLUE}🗄️ Starting PgAdmin...${NC}"
docker-compose up -d pgadmin

# Start the main application
echo -e "${BLUE}🚀 Starting Passwordless Multi-Auth Application...${NC}"
docker-compose up -d passwordless-app

echo ""
echo -e "${GREEN}🎉 Passwordless Multi-Auth App is starting up!${NC}"
echo ""
echo -e "${BLUE}📋 Running Services:${NC}"
docker-compose ps --format "table {{.Name}}\\t{{.Status}}\\t{{.Ports}}"
echo ""
echo -e "${BLUE}🔗 Access Points:${NC}"
echo "   • Passwordless Multi-Auth App: http://localhost:8585"
echo "   • PgAdmin: http://localhost:5050 (admin@example.com/admin)"
echo "   • Mailpit (Email): http://localhost:8025"
echo "   • PostgreSQL: localhost:5432"
echo "   • Redis: localhost:6379"
echo ""
echo -e "${BLUE}🔧 Useful Commands:${NC}"
echo "   • View app logs: docker-compose logs -f passwordless-app"
echo "   • Stop services: docker-compose stop postgres redis mailpit passwordless-app pgadmin"
echo "   • Restart app: docker-compose restart passwordless-app"