#!/bin/bash

# Honeypot Management System - Comprehensive Test Script
# Tests HTTP API, SSH, MySQL, and PostgreSQL honeypots
# Creates 20+ different attack scenarios

# Remove set -e to prevent script from exiting on first error
# set -e

# Configuration
HONEYPOT_HOST="localhost"
HTTP_PORT="8081"  # Updated to match your actual port
SSH_PORT="2222"
MYSQL_PORT="3307"
POSTGRES_PORT="5433"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Logging
LOG_FILE="honeypot_test_$(date +%Y%m%d_%H%M%S).log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_test() {
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${YELLOW}[TEST $TOTAL_TESTS] $1${NC}"
    log "TEST $TOTAL_TESTS: $1"
}

print_success() {
    PASSED_TESTS=$((PASSED_TESTS + 1))
    echo -e "${GREEN}✓ PASS: $1${NC}"
    log "PASS: $1"
}

print_failure() {
    FAILED_TESTS=$((FAILED_TESTS + 1))
    echo -e "${RED}✗ FAIL: $1${NC}"
    log "FAIL: $1"
}

check_service() {
    local service=$1
    local port=$2
    if nc -z "$HONEYPOT_HOST" "$port" 2>/dev/null; then
        print_success "$service is running on port $port"
        return 0
    else
        print_failure "$service is not running on port $port"
        return 1
    fi
}

wait_for_service() {
    local service=$1
    local port=$2
    local timeout=30
    local count=0

    echo "Waiting for $service on port $port..."
    while ! nc -z "$HONEYPOT_HOST" "$port" 2>/dev/null; do
        sleep 1
        count=$((count + 1))
        if [ $count -ge $timeout ]; then
            print_failure "$service failed to start within $timeout seconds"
            return 1
        fi
    done
    print_success "$service is ready"
    return 0
}

# =============================================================================
# HTTP API TESTS
# =============================================================================

test_http_honeypots() {
    print_header "HTTP API HONEYPOT TESTS"

    # Test 1: Normal blog access
    print_test "Normal blog access"
    response=$(curl -s -w "%{http_code}" -o /dev/null "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/getAllBlogs")
    if [ "$response" = "200" ]; then
        print_success "Blog endpoint accessible"
    else
        print_failure "Blog endpoint returned: $response"
    fi

    # Test 2: SQL Injection in blog endpoint
    print_test "SQL Injection attack on blog endpoint"
    response=$(curl -s -w "%{http_code}" -o /dev/null "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/getAllBlogs?id=1' OR '1'='1" || echo "000")
    echo "Debug: SQL injection test response code: $response"
    if [ "$response" = "400" ]; then
        print_success "SQL injection detected and blocked"
    else
        print_failure "SQL injection not detected, response: $response"
    fi

    # Test 3: XSS attack in post creation
    print_test "XSS attack in post creation"
    response=$(curl -s -w "%{http_code}" -o /dev/null \
        -H "Content-Type: application/json" \
        -d '{"content":"<script>alert(\"XSS\")</script>"}' \
        "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/posts" || echo "000")
    echo "Debug: XSS test response code: $response"
    if [ "$response" = "400" ]; then
        print_success "XSS attack detected and blocked"
    else
        print_failure "XSS attack not detected, response: $response"
    fi

    # Test 4: Command injection attempt
    print_test "Command injection in post content"
    response=$(curl -s -w "%{http_code}" -o /dev/null \
        -H "Content-Type: application/json" \
        -d '{"content":"test; ls -la; cat /etc/passwd"}' \
        "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/posts")
    if [ "$response" = "400" ]; then
        print_success "Command injection detected and blocked"
    else
        print_failure "Command injection not detected, response: $response"
    fi

    # Test 5: Directory traversal attack
    print_test "Directory traversal attack"
    response=$(curl -s -w "%{http_code}" -o /dev/null \
        "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/posts/../../../etc/passwd")
    if [ "$response" = "400" ]; then
        print_success "Directory traversal detected and blocked"
    else
        print_failure "Directory traversal not detected, response: $response"
    fi

    # Test 6: Malicious file upload
    print_test "Malicious file upload attempt"
    response=$(curl -s -w "%{http_code}" -o /dev/null \
        -F "file=malware.exe" \
        "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/upload")
    if [ "$response" = "400" ]; then
        print_success "Malicious file upload detected and blocked"
    else
        print_failure "Malicious file upload not detected, response: $response"
    fi

    # Test 7: Brute force login attempts
    print_test "Brute force login attempts"
    for i in {1..5}; do
        curl -s -o /dev/null \
            -H "Content-Type: application/json" \
            -d '{"username":"admin","password":"password'$i'"}' \
            "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/login"
    done
    print_success "Brute force login attempts completed"

    # Test 8: Common attack credentials
    print_test "Common attack credentials"
    for cred in "admin:admin" "root:root" "administrator:password" "test:test"; do
        username=$(echo "$cred" | cut -d: -f1)
        password=$(echo "$cred" | cut -d: -f2)
        curl -s -o /dev/null \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"$username\",\"password\":\"$password\"}" \
            "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/login"
    done
    print_success "Common credentials test completed"

    # Test 9: Admin panel access attempt
    print_test "Admin panel access attempt"
    response=$(curl -s -w "%{http_code}" -o /dev/null \
        "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/admin")
    if [ "$response" = "403" ]; then
        print_success "Admin panel access attempt logged"
    else
        print_failure "Admin panel response unexpected: $response"
    fi

    # Test 10: WordPress admin access attempt
    print_test "WordPress admin access attempt"
    response=$(curl -s -w "%{http_code}" -o /dev/null \
        "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/wp-admin/")
    if [ "$response" = "404" ]; then
        print_success "WordPress admin access attempt logged"
    else
        print_failure "WordPress admin response unexpected: $response"
    fi

    # Test 11: Config file access attempt
    print_test "Config file access attempt"
    response=$(curl -s -w "%{http_code}" -o /dev/null \
        "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/config.php")
    if [ "$response" = "404" ]; then
        print_success "Config file access attempt logged"
    else
        print_failure "Config file response unexpected: $response"
    fi
}

# =============================================================================
# SSH HONEYPOT TESTS
# =============================================================================

test_ssh_honeypot() {
    print_header "SSH HONEYPOT TESTS"

    if ! check_service "SSH Honeypot" "$SSH_PORT"; then
        return
    fi

    # Test 12: SSH connection attempt
    print_test "SSH connection and banner test"
    banner=$(timeout 5 nc "$HONEYPOT_HOST" "$SSH_PORT" < /dev/null 2>/dev/null | head -1)
    if [[ "$banner" == *"SSH-2.0"* ]]; then
        print_success "SSH banner received: $banner"
    else
        print_failure "SSH banner not received or incorrect"
    fi

    # Test 13: SSH brute force simulation
    print_test "SSH brute force simulation"
    for user in "root" "admin" "test" "guest" "ubuntu"; do
        for pass in "password" "123456" "admin" "root" "test"; do
            (
                sleep 1
                echo "$user"
                sleep 1
                echo "$pass"
                sleep 1
            ) | timeout 10 nc "$HONEYPOT_HOST" "$SSH_PORT" >/dev/null 2>&1 &
        done
    done
    wait
    print_success "SSH brute force simulation completed"
}

# =============================================================================
# DATABASE HONEYPOT TESTS
# =============================================================================

test_mysql_honeypot() {
    print_header "MYSQL HONEYPOT TESTS"

    if ! check_service "MySQL Honeypot" "$MYSQL_PORT"; then
        return
    fi

    # Test 14: MySQL connection attempt with mysql client (if available)
    print_test "MySQL connection attempt"
    if command -v mysql >/dev/null 2>&1; then
        timeout 10 mysql -h "$HONEYPOT_HOST" -P "$MYSQL_PORT" -u "root" -p"password" 2>/dev/null || true
        print_success "MySQL connection attempt completed"
    else
        # Alternative test using telnet/nc
        (
            sleep 2
            echo "quit"
        ) | timeout 10 nc "$HONEYPOT_HOST" "$MYSQL_PORT" >/dev/null 2>&1 || true
        print_success "MySQL connection test completed (no mysql client)"
    fi

    # Test 15: Multiple MySQL connection attempts with different users
    print_test "MySQL brute force simulation"
    for user in "root" "admin" "mysql" "test" "user"; do
        for pass in "password" "123456" "admin" "root" "mysql"; do
            if command -v mysql >/dev/null 2>&1; then
                timeout 5 mysql -h "$HONEYPOT_HOST" -P "$MYSQL_PORT" -u "$user" -p"$pass" 2>/dev/null || true
            else
                timeout 5 nc "$HONEYPOT_HOST" "$MYSQL_PORT" < /dev/null >/dev/null 2>&1 || true
            fi
        done
    done
    print_success "MySQL brute force simulation completed"
}

test_postgresql_honeypot() {
    print_header "POSTGRESQL HONEYPOT TESTS"

    if ! check_service "PostgreSQL Honeypot" "$POSTGRES_PORT"; then
        return
    fi

    # Test 16: PostgreSQL connection attempt
    print_test "PostgreSQL connection attempt"
    if command -v psql >/dev/null 2>&1; then
        timeout 10 psql -h "$HONEYPOT_HOST" -p "$POSTGRES_PORT" -U "postgres" -d "postgres" 2>/dev/null || true
        print_success "PostgreSQL connection attempt completed"
    else
        # Alternative test using nc
        (
            sleep 2
            echo "quit"
        ) | timeout 10 nc "$HONEYPOT_HOST" "$POSTGRES_PORT" >/dev/null 2>&1 || true
        print_success "PostgreSQL connection test completed (no psql client)"
    fi

    # Test 17: PostgreSQL brute force simulation
    print_test "PostgreSQL brute force simulation"
    for user in "postgres" "admin" "root" "test" "user"; do
        for pass in "password" "123456" "admin" "postgres" "test"; do
            if command -v psql >/dev/null 2>&1; then
                PGPASSWORD="$pass" timeout 5 psql -h "$HONEYPOT_HOST" -p "$POSTGRES_PORT" -U "$user" -d "postgres" 2>/dev/null || true
            else
                timeout 5 nc "$HONEYPOT_HOST" "$POSTGRES_PORT" < /dev/null >/dev/null 2>&1 || true
            fi
        done
    done
    print_success "PostgreSQL brute force simulation completed"
}

# =============================================================================
# ADVANCED ATTACK SIMULATIONS
# =============================================================================

test_advanced_attacks() {
    print_header "ADVANCED ATTACK SIMULATIONS"

    # Test 18: Mixed attack patterns
    print_test "Mixed attack patterns simulation"

    # Combine different attack vectors
    curl -s -o /dev/null "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/getAllBlogs?id=1' UNION SELECT * FROM users--" &
    curl -s -o /dev/null -H "Content-Type: application/json" -d '{"content":"<img src=x onerror=alert(1)>"}' "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/posts" &
    timeout 5 nc "$HONEYPOT_HOST" "$SSH_PORT" < /dev/null >/dev/null 2>&1 &
    timeout 5 nc "$HONEYPOT_HOST" "$MYSQL_PORT" < /dev/null >/dev/null 2>&1 &

    wait
    print_success "Mixed attack patterns completed"

    # Test 19: Rapid fire attacks
    print_test "Rapid fire attack simulation"
    for i in {1..10}; do
        curl -s -o /dev/null "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/admin" &
        curl -s -o /dev/null "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/wp-admin/" &
        curl -s -o /dev/null "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/config.php" &
    done
    wait
    print_success "Rapid fire attacks completed"

    # Test 20: Persistence simulation
    print_test "Persistence attack simulation"
    for i in {1..5}; do
        # Multiple login attempts
        curl -s -o /dev/null -H "Content-Type: application/json" -d '{"username":"attacker","password":"hack'$i'"}' "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/login"

        # File upload attempts
        curl -s -o /dev/null -F "file=backdoor$i.php" "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/upload"

        # Admin access attempts
        curl -s -o /dev/null "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/admin"

        sleep 1
    done
    print_success "Persistence attack simulation completed"
}

# =============================================================================
# STRESS TESTING
# =============================================================================

test_stress_scenarios() {
    print_header "STRESS TEST SCENARIOS"

    # Test 21: Concurrent connections
    print_test "Concurrent connection stress test"

    # Launch multiple concurrent attacks
    for i in {1..20}; do
        (
            curl -s -o /dev/null "http://$HONEYPOT_HOST:$HTTP_PORT/api/honeypot/getAllBlogs?attack=sql$i"
            timeout 3 nc "$HONEYPOT_HOST" "$SSH_PORT" < /dev/null >/dev/null 2>&1
            timeout 3 nc "$HONEYPOT_HOST" "$MYSQL_PORT" < /dev/null >/dev/null 2>&1
        ) &
    done

    wait
    print_success "Concurrent connection stress test completed"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    print_header "HONEYPOT MANAGEMENT SYSTEM - COMPREHENSIVE TEST SUITE"
    log "Starting comprehensive honeypot test suite"

    # Check if honeypot services are running
    echo "Checking honeypot services..."
    wait_for_service "HTTP API" "$HTTP_PORT"

    # Run all test suites
    test_http_honeypots
    test_ssh_honeypot
    test_mysql_honeypot
    test_postgresql_honeypot
    test_advanced_attacks
    test_stress_scenarios

    # Final report
    print_header "TEST RESULTS SUMMARY"
    echo -e "${BLUE}Total Tests: $TOTAL_TESTS${NC}"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"

    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests completed successfully!${NC}"
        log "All tests completed successfully"
    else
        echo -e "${YELLOW}⚠️  Some tests failed. Check the log for details.${NC}"
        log "Some tests failed - Total: $TOTAL_TESTS, Passed: $PASSED_TESTS, Failed: $FAILED_TESTS"
    fi

    echo -e "${BLUE}Detailed log saved to: $LOG_FILE${NC}"

    # Show some recent attack events (if you have an endpoint for this)
    echo -e "\n${BLUE}Recent attack events should now be visible in your honeypot dashboard${NC}"
}

# Check dependencies
check_dependencies() {
    echo "Checking dependencies..."

    if ! command -v curl >/dev/null 2>&1; then
        echo "Error: curl is required but not installed"
        exit 1
    fi

    if ! command -v nc >/dev/null 2>&1; then
        echo "Warning: netcat (nc) is recommended for network tests"
    fi

    echo "Dependencies check completed"
}

# Cleanup function
cleanup() {
    echo "Cleaning up background processes..."
    # Kill background jobs more gracefully
    for job in $(jobs -p); do
        kill "$job" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}

# Set up signal handlers - only cleanup on specific signals
trap cleanup EXIT

# Run the test suite
check_dependencies
main

exit 0
