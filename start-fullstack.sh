#!/bin/bash

# Start Full Monitoring Stack
# Starts everything: App + ELK + Prometheus/Grafana + All monitoring tools

set -e

# All services live in docker-compose-full-stack.yml
COMPOSE="docker-compose -f docker-compose-full-stack.yml"

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🚀 Starting Passwordless Multi-Auth Full Monitoring Stack${NC}"
echo -e "${YELLOW}=================================${NC}"
echo "This will start ALL services for complete monitoring!"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker and docker-compose are available ${NC}"
echo ""
echo -e "${BLUE}🐳 Phase 1: Starting postgres, redis and mailpit containers...${NC}"

${COMPOSE} up -d postgres redis mailpit

echo -e "${YELLOW}⏳ Waiting for core services...${NC}"
sleep 15

# Check PostgreSQL
timeout=60
counter=0
while ! ${COMPOSE} exec postgres pg_isready -U passwordless > /dev/null 2>&1; do
    sleep 2
    counter=$((counter + 2))
    if [ $counter -ge $timeout ]; then
        echo -e "${RED}❌ PostgreSQL failed to start${NC}"
        exit 1
    fi
    printf "   PostgreSQL... (%ds/%ds)\\r" $counter $timeout
done

echo -e "${GREEN}✅ Postgres, redis and mailpit containers started!  ${NC}"
echo ""
echo -e "${BLUE}🐳 Phase 2: Starting monitoring (prometheus, grafana) containers...${NC}"
${COMPOSE} up -d prometheus grafana node-exporter redis-exporter postgres-exporter
echo -e "${GREEN}✅ Monitoring started!${NC}"
echo ""
# Create the host log directory shared with filebeat
echo -e "${BLUE}📁 Phase 3: Creating necessary directories...${NC}"

mkdir -p logs

echo -e "${GREEN}✅ Directories created!${NC}"
echo ""
# Start the ELK Stack
echo -e "${BLUE}🐳 Phase 4: Starting Elasticsearch container...${NC}"
${COMPOSE} up -d elasticsearch

echo -e "${YELLOW}⏳ Waiting for Elasticsearch...${NC}"
timeout=300
counter=0
while ! curl -s "http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=1s" > /dev/null 2>&1; do
    sleep 5
    counter=$((counter + 5))
    if [ $counter -ge $timeout ]; then
        echo -e "${RED}❌ Elasticsearch failed to start${NC}"
        exit 1
    fi
    printf "   Elasticsearch... (%ds/%ds)\\r" $counter $timeout
done
echo -e "${GREEN}✅ Elasticsearch started!${NC}"
echo ""
echo -e "${BLUE}📊 Phase 5: Starting ELK Stack (logstash, kibana, filebeat)...${NC}"
${COMPOSE} up -d logstash kibana filebeat

echo -e "${YELLOW}⏳ Waiting for Kibana...${NC}"
timeout=300
counter=0
while ! curl -s http://localhost:5601/api/status > /dev/null 2>&1; do
    sleep 10
    counter=$((counter + 10))
    if [ $counter -ge $timeout ]; then
        echo -e "${RED}❌ Kibana failed to start${NC}"
        exit 1
    fi
    printf "   Kibana... (%ds/%ds)\\r" $counter $timeout
done
echo -e "${GREEN}✅ ELK Stack started! ${NC}"
echo ""
echo -e "${BLUE}🚀 Phase 6: Starting spring boot app and pgadmin...${NC}"
${COMPOSE} up -d passwordless-app pgadmin
echo -e "${GREEN}✅ Spring boot app and pgadmin started! ${NC}"
echo ""
echo -e "${BLUE}⚙️ Phase 7: Setting up Elasticsearch logs templates...${NC}"
sleep 10
# Security Audit Index Template
curl -X PUT "localhost:9200/_index_template/security-audit-template" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["security-audit-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.refresh_interval": "5s"
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "audit": {
          "properties": {
            "eventType": {
              "type": "keyword"
            },
            "userId": {
              "type": "keyword"
            },
            "clientIp": {
              "type": "ip"
            },
            "userAgent": {
              "type": "text",
              "fields": {
                "keyword": {
                  "type": "keyword",
                  "ignore_above": 256
                }
              }
            },
            "sessionId": {
              "type": "keyword"
            }
          }
        },
        "threat_level": {
          "type": "keyword"
        },
        "source_ip": {
          "type": "ip"
        }
      }
    }
  }
}'

# Application Logs Index Template
curl -X PUT "localhost:9200/_index_template/application-logs-template" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["application-logs-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.refresh_interval": "10s"
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "log_level": {
          "type": "keyword"
        },
        "class_name": {
          "type": "keyword"
        },
        "log_message": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 1024
            }
          }
        },
        "thread": {
          "type": "keyword"
        },
        "response_time": {
          "type": "integer"
        },
        "memory_usage": {
          "type": "long"
        },
        "has_exception": {
          "type": "boolean"
        }
      }
    }
  }
}'

echo -e "${GREEN}✅ Elasticsearch logs templates created${NC}"
echo ""
# Wait a bit for everything to settle
sleep 10

# Import Kibana index patterns and dashboards
echo -e "${BLUE}⚙️ Phase 8: Configuring Kibana index patterns...${NC}"

curl -s -X POST "localhost:5601/api/saved_objects/index-pattern/security-audit-*" \
    -H 'Content-Type: application/json' -H 'kbn-xsrf: true' \
    -d'{"attributes": {"title": "security-audit-*", "timeFieldName": "@timestamp"}}' > /dev/null \
    && echo -e "${GREEN}✅ Kibana patterns configured ${NC}"

echo ""
echo -e "${GREEN}🎉 Full Monitoring Stack is ready!${NC}"
echo ""
echo -e "${BLUE}📋 All Running Services:${NC}"
${COMPOSE} ps --format "table {{.Name}}\\t{{.Status}}\\t{{.Ports}}"
echo ""
echo -e "${BLUE}🔗 Access Points:${NC}"
echo "   🚀 Main Application:"
echo "      • Passwordless Multi-Auth App: http://localhost:8585"
echo "      • PgAdmin: http://localhost:5050 (admin@example.com / PGADMIN_PASSWORD from .env)"
echo "      • Mailpit: http://localhost:8025"
echo ""
echo "   📊 Monitoring & Metrics:"
echo "      • Grafana: http://localhost:3000 (user: admin, password: GRAFANA_ADMIN_PASSWORD from .env)"
echo "      • Prometheus: http://localhost:9090"
echo ""
echo "   🔍 Log Analysis:"
echo "      • Kibana: http://localhost:5601"
echo "      • Elasticsearch: http://localhost:9200"
echo "      • Logstash: http://localhost:9600"
echo ""
echo -e "${BLUE}🔧 Management Commands:${NC}"
echo "   • Stop all: ${COMPOSE} down"
echo "   • View all logs: ${COMPOSE} logs -f"
echo "   • Restart service: ${COMPOSE} restart [service-name]"
echo "   • Scale service: ${COMPOSE} up -d --scale [service-name]=2"
echo ""
echo -e "${BLUE}📖 Next Steps:${NC}"
echo "   1. Configure Grafana dashboards for metrics visualization"
echo "   2. Open Kibana at http://localhost:5601"
echo "   3. Go to Management > Stack Management > Index Patterns"
echo "   4. Create index patterns for your log indices"
echo "   5. Navigate to Discover to explore your logs"
echo "   6. Configure alerting rules from elk/alerting-rules.txt"
echo "   7. Import predefined queries from elk/predefined-queries.txt"
echo ""
echo -e "${BLUE}🔧 Troubleshooting:${NC}"
echo "   • Check container logs: docker-compose logs [service-name]"
echo "   • Restart services: docker-compose restart [service-name]"
echo "   • Clean restart: docker-compose down && docker-compose up -d"
echo ""
echo -e "${BLUE}📖 Documentation:${NC}"
echo "   • Kibana User Guide: https://www.elastic.co/guide/en/kibana/current/index.html"
echo "   • Elasticsearch Query DSL: https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl.html"
echo "   • Logstash Configuration: https://www.elastic.co/guide/en/logstash/current/configuration.html"