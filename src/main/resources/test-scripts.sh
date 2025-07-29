#!/bin/bash

# Honeypot Management System Testing Script
# This script tests all honeypot services including web, SSH, and database honeypots

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HONEYPOT_HOST="localhost"
WEB_PORT="8081"
SSH_PORT="2222"
MYSQL_PORT="3307"
POSTGRES_PORT="5433"

echo -e "${BLUE}🍯 Starting Honeypot Management System Testing${NC}"
echo "=================================================="

# Function to print test header
print_test_header() {
    echo -e "\n${YELLOW}$1${NC}"
    echo "----------------------------------------"
}

# Function to test web honeypot endpoints
test_web_honeypot() {
    print_test_header "Testing Web Honeypot Endpoints"

    BASE_URL="http://${HONEYPOT_HOST}:${WEB_PORT}/api/honeypot"

    # Test 1: Normal blog access
    echo -e "${GREEN}Test 1: Normal blog access${NC}"
    curl -s -X GET "${BASE_URL}/getAllBlogs" \
         -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
         | jq . 2>/dev/null || echo "Response received"

    # Test 2: SQL Injection attempt
    echo -e "\n${GREEN}Test 2: SQL Injection attempt${NC}"
    curl -s -X GET "${BASE_URL}/getAllBlogs?id=1' OR '1'='1" \
         -H "User-Agent: AttackBot/1.0" \
         | jq . 2>/dev/null || echo "SQL injection attempt logged"

    # Test 3: XSS attempt in post creation
    echo -e "\n${GREEN}Test 3: XSS attempt in post creation${NC}"
    curl -s -X POST "${BASE_URL}/posts" \
         -H "Content-Type: application/json" \
         -H "User-Agent: XSSBot/1.0" \
         -d '{"content":"<script>alert(\"XSS\")</script>","title":"Malicious Post"}' \
         | jq . 2>/dev/null || echo "XSS attempt logged"

    # Test 4: Directory traversal attempt
    echo -e "\n${GREEN}Test 4: Directory traversal attempt${NC}"
    curl -s -X GET "${BASE_URL}/posts/../../../etc/passwd" \
         -H "User-Agent: DirTraversalBot/1.0" \
         | jq . 2>/dev/null || echo "Directory traversal attempt logged"

    # Test 5: Brute force login attempts
    echo -e "\n${GREEN}Test 5: Brute force login attempts${NC}"
    for i in {1..5}; do
        curl -s -X POST "${BASE_URL}/login" \
             -H "Content-Type: application/json" \
             -H "User-Agent: BruteForceBot/1.0" \
             -d "{\"username\":\"admin\",\"password\":\"password${i}\"}" \
             | jq . 2>/dev/null || echo "Login attempt ${i} logged"
        sleep 1
    done

    # Test 6: Command injection attempt
    echo -e "\n${GREEN}Test 6: Command injection attempt${NC}"
    curl -s -X POST "${BASE_URL}/posts" \
         -H "Content-Type: application/json" \
         -H "User-Agent: CmdInjectionBot/1.0" \
         -d '{"content":"Hello; cat /etc/passwd","title":"Command Injection"}' \
         | jq . 2>/dev/null || echo "Command injection attempt logged"

    # Test 7: Admin panel access attempt
    echo -e "\n${GREEN}Test 7: Admin panel access attempt${NC}"
    curl -s -X GET "${BASE_URL}/admin" \
         -H "User-Agent: AdminHunter/1.0" \
         | jq . 2>/dev/null || echo "Admin access attempt logged"

    # Test 8: WordPress admin access attempt
    echo -e "\n${GREEN}Test 8: WordPress admin access attempt${NC}"
    curl -s -X GET "${BASE_URL}/wp-admin/login.php" \
         -H "User-Agent: WPScanner/1.0" \
         | jq . 2>/dev/null || echo "WordPress access attempt logged"

    # Test 9: Malicious file upload attempt
    echo -e "\n${GREEN}Test 9: Malicious file upload attempt${NC}"
    curl -s -X POST "${BASE_URL}/upload" \
         -H "User-Agent: FileUploadBot/1.0" \
         -F "file=malware.exe" \
         | jq . 2>/dev/null || echo "Malicious upload attempt logged"
}

# Function to test SSH honeypot
test_ssh_honeypot() {
    print_test_header "Testing SSH Honeypot"

    # Test SSH connection attempts with different credentials
    echo -e "${GREEN}Test 1: SSH connection with common credentials${NC}"

    # Common username/password combinations
    credentials=(
        "root:password"
        "admin:admin"
        "root:123456"
        "admin:password"
        "test:test"
    )

    for cred in "${credentials[@]}"; do
        IFS=':' read -r username password <<< "$cred"
        echo -e "Testing SSH with ${username}:${password}"

        # Use expect to automate SSH interaction
        expect << EOF 2>/dev/null
spawn ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no ${username}@${HONEYPOT_HOST} -p ${SSH_PORT}
expect {
    "password:" {
        send "${password}\r"
        expect eof
    }
    "Please enter username:" {
        send "${username}\r"
        expect "Password:"
        send "${password}\r"
        expect eof
    }
    timeout {
        exit 0
    }
    eof {
        exit 0
    }
    }

EOF
        sleep 2
    done
}

# Function to test MySQL honeypot
test_mysql_honeypot() {
    print_test_header "Testing MySQL Honeypot"

    # Test MySQL connection attempts
    echo -e "${GREEN}Test 1: MySQL connection attempts${NC}"

    mysql_users=("root" "admin" "mysql" "user" "test")
    mysql_passwords=("" "password" "123456" "admin" "root")

    for user in "${mysql_users[@]}"; do
        for pass in "${mysql_passwords[@]}"; do
            echo -e "Testing MySQL with ${user}:${pass}"

            if [ -z "$pass" ]; then
                # Empty password
                timeout 10 mysql -h ${HONEYPOT_HOST} -P ${MYSQL_PORT} -u "${user}" \
                    -e "SELECT 1;" 2>/dev/null || echo "MySQL connection attempt logged"
            else
                # With password
                timeout 10 mysql -h ${HONEYPOT_HOST} -P ${MYSQL_PORT} -u "${user}" -p"${pass}" \
                    -e "SELECT 1;" 2>/dev/null || echo "MySQL connection attempt logged"
            fi
            sleep 1
        done
    done
}

# Function to test PostgreSQL honeypot
test_postgresql_honeypot() {
    print_test_header "Testing PostgreSQL Honeypot"

    # Test PostgreSQL connection attempts
    echo -e "${GREEN}Test 1: PostgreSQL connection attempts${NC}"

    pg_users=("postgres" "admin" "root" "user" "test")
    pg_passwords=("password" "123456" "admin" "postgres" "")

    for user in "${pg_users[@]}"; do
        for pass in "${pg_passwords[@]}"; do
            echo -e "Testing PostgreSQL with ${user}:${pass}"

            if [ -z "$pass" ]; then
                # No password
                timeout 10 psql -h ${HONEYPOT_HOST} -p ${POSTGRES_PORT} -U ${user} \
                    -d postgres -c "SELECT 1;" 2>/dev/null || echo "PostgreSQL connection attempt logged"
            else
                # With password
                PGPASSWORD=${pass} timeout 10 psql -h ${HONEYPOT_HOST} -p ${POSTGRES_PORT} \
                    -U "${user}" -d postgres -c "SELECT 1;" 2>/dev/null || echo "PostgreSQL connection attempt logged"
            fi
            sleep 1
        done
    done
}

# Function to test dashboard endpoints
test_dashboard_endpoints() {
    print_test_header "Testing Dashboard Endpoints"

    BASE_URL="http://${HONEYPOT_HOST}:${WEB_PORT}/api/dashboard"

    echo -e "${GREEN}Test 1: Dashboard statistics${NC}"
    curl -s -X GET "${BASE_URL}/stats" | jq . 2>/dev/null || echo "Stats endpoint tested"

    echo -e "\n${GREEN}Test 2: Recent attacks${NC}"
    curl -s -X GET "${BASE_URL}/attacks?page=0&size=10" | jq . 2>/dev/null || echo "Attacks endpoint tested"

    echo -e "\n${GREEN}Test 3: Top attackers${NC}"
    curl -s -X GET "${BASE_URL}/top-attackers" | jq . 2>/dev/null || echo "Top attackers endpoint tested"

    echo -e "\n${GREEN}Test 4: Attack timeline${NC}"
    curl -s -X GET "${BASE_URL}/attack-timeline?hours=24" | jq . 2>/dev/null || echo "Timeline endpoint tested"

    echo -e "\n${GREEN}Test 5: Threat intelligence${NC}"
    curl -s -X GET "${BASE_URL}/threat-intelligence" | jq . 2>/dev/null || echo "Threat intelligence endpoint tested"

    echo -e "\n${GREEN}Test 6: System health${NC}"
    curl -s -X GET "${BASE_URL}/health" | jq . 2>/dev/null || echo "Health endpoint tested"
}

# Function to generate load test
generate_load_test() {
    print_test_header "Generating Load Test"

    echo -e "${GREEN}Generating multiple concurrent attacks...${NC}"

    BASE_URL="http://${HONEYPOT_HOST}:${WEB_PORT}/api/honeypot"

    # Run multiple attacks in parallel
    for i in {1..10}; do
        {
            # Random attack type
            case $((RANDOM % 4)) in
                0)
                    curl -s -X GET "${BASE_URL}/getAllBlogs?id=1' UNION SELECT * FROM users--" \
                         -H "User-Agent: LoadTestBot-${i}/1.0" > /dev/null
                    ;;
                1)
                    curl -s -X POST "${BASE_URL}/login" \
                         -H "Content-Type: application/json" \
                         -H "User-Agent: LoadTestBot-${i}/1.0" \
                         -d "{\"username\":\"admin${i}\",\"password\":\"pass${i}\"}" > /dev/null
                    ;;
                2)
                    curl -s -X POST "${BASE_URL}/posts" \
                         -H "Content-Type: application/json" \
                         -H "User-Agent: LoadTestBot-${i}/1.0" \
                         -d "{\"content\":\"<script>alert('test${i}')</script>\"}" > /dev/null
                    ;;
                3)
                    curl -s -X GET "${BASE_URL}/posts/../../../etc/passwd" \
                         -H "User-Agent: LoadTestBot-${i}/1.0" > /dev/null
                    ;;
            esac
        } &
    done

    # Wait for all background jobs to complete
    wait
    echo -e "${GREEN}Load test completed${NC}"
}

# Function to check service availability
check_services() {
    print_test_header "Checking Service Availability"

    # Check web service
    if curl -s --connect-timeout 5 "http://${HONEYPOT_HOST}:${WEB_PORT}/api/dashboard/health" > /dev/null; then
        echo -e "${GREEN}✓ Web Honeypot Service: AVAILABLE${NC}"
    else
        echo -e "${RED}✗ Web Honeypot Service: UNAVAILABLE${NC}"
    fi

    # Check SSH service
    if timeout 5 bash -c "echo > /dev/tcp/${HONEYPOT_HOST}/${SSH_PORT}" 2>/dev/null; then
        echo -e "${GREEN}✓ SSH Honeypot Service: AVAILABLE${NC}"
    else
        echo -e "${RED}✗ SSH Honeypot Service: UNAVAILABLE${NC}"
    fi

    # Check MySQL service
    if timeout 5 bash -c "echo > /dev/tcp/${HONEYPOT_HOST}/${MYSQL_PORT}" 2>/dev/null; then
        echo -e "${GREEN}✓ MySQL Honeypot Service: AVAILABLE${NC}"
    else
        echo -e "${RED}✗ MySQL Honeypot Service: UNAVAILABLE${NC}"
    fi

    # Check PostgreSQL service
    if timeout 5 bash -c "echo > /dev/tcp/${HONEYPOT_HOST}/${POSTGRES_PORT}" 2>/dev/null; then
        echo -e "${GREEN}✓ PostgreSQL Honeypot Service: AVAILABLE${NC}"
    else
        echo -e "${RED}✗ PostgreSQL Honeypot Service: UNAVAILABLE${NC}"
    fi
}

# Main execution
main() {
    echo -e "${BLUE}Honeypot Management System - Comprehensive Test Suite${NC}"
    echo -e "${BLUE}====================================================${NC}"

    # Check if required tools are available
    command -v curl >/dev/null 2>&1 || { echo -e "${RED}curl is required but not installed.${NC}" >&2; }
    command -v jq >/dev/null 2>&1 || { echo -e "${YELLOW}jq is not installed. JSON output will be raw.${NC}" >&2; }

    # Check service availability first
    check_services

    # Run tests based on arguments or run all
    if [ $# -eq 0 ]; then
        echo -e "\n${BLUE}Running all tests...${NC}"
        test_web_honeypot
        test_ssh_honeypot
        test_mysql_honeypot
        test_postgresql_honeypot
#        test_dashboard_endpoints
#        generate_load_test
    else
        case $1 in
            "web")
                test_web_honeypot
                ;;
            "ssh")
                test_ssh_honeypot
                ;;
            "mysql")
                test_mysql_honeypot
                ;;
            "postgres")
                test_postgresql_honeypot
                ;;
            "dashboard")
                test_dashboard_endpoints
                ;;
            "load")
                generate_load_test
                ;;
            "check")
                check_services
                ;;
            *)
                echo "Usage: $0 [web|ssh|mysql|postgres|dashboard|load|check]"
                echo "       $0 (run all tests)"
                exit 1
                ;;
        esac
    fi

    echo -e "\n${GREEN}🎉 Testing completed! Check your honeypot dashboard for logged attacks.${NC}"
    echo -e "${BLUE}Dashboard URL: http://${HONEYPOT_HOST}:${WEB_PORT}${NC}"
}

# Execute main function with all arguments
main "$@"
