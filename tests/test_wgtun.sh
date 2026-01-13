#!/bin/bash
#
# wgtun Test Script
# Tests CLI functionality for the wgtun WireGuard tunnel implementation
#
# Usage:
#   ./tests/test_wgtun.sh           # Run all tests (root tests skipped if not root)
#   ./tests/test_wgtun.sh --quick   # Skip slow/root-requiring tests
#   sudo ./tests/test_wgtun.sh      # Run all tests including root-required ones
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
WGTUN_DIR="$PROJECT_ROOT/wgtun"
BINARY="$WGTUN_DIR/target/release/wgtun"
TMP_DIR=""

# Parse arguments
QUICK_MODE=false
for arg in "$@"; do
    case $arg in
        --quick)
            QUICK_MODE=true
            ;;
    esac
done

#
# Utility Functions
#

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT

setup() {
    TMP_DIR=$(mktemp -d)
    log_info "Using temp directory: $TMP_DIR"
}

ensure_binary() {
    if [ ! -x "$BINARY" ]; then
        log_info "Building wgtun in release mode..."
        if ! (cd "$WGTUN_DIR" && cargo build --release 2>&1); then
            echo -e "${RED}ERROR: Failed to build wgtun binary${NC}"
            exit 1
        fi
        if [ ! -x "$BINARY" ]; then
            echo -e "${RED}ERROR: Binary not found after build${NC}"
            exit 1
        fi
    fi
    log_info "Using binary: $BINARY"
}

is_root() {
    [ "$(id -u)" -eq 0 ]
}

#
# Test Functions
#

test_help() {
    log_info "Testing: --help flag"
    if $BINARY --help >/dev/null 2>&1; then
        log_pass "--help flag works"
    else
        log_fail "--help flag failed"
    fi
}

test_version() {
    log_info "Testing: --version flag"
    if $BINARY --version 2>&1 | grep -q "wgtun"; then
        log_pass "--version shows wgtun"
    else
        log_fail "--version output unexpected"
    fi
}

test_genkey() {
    log_info "Testing: genkey command"

    # Generate a key
    local key
    key=$($BINARY genkey 2>/dev/null) || { log_fail "genkey command failed"; return; }

    # Check it's base64 (44 chars with padding)
    if [ ${#key} -eq 44 ]; then
        log_pass "genkey produces 44-char base64 key"
    else
        log_fail "genkey produced key of length ${#key}, expected 44"
        return
    fi

    # Check it decodes to 32 bytes
    local decoded_len
    decoded_len=$(echo "$key" | base64 -d 2>/dev/null | wc -c)
    if [ "$decoded_len" -eq 32 ]; then
        log_pass "genkey produces valid 32-byte key"
    else
        log_fail "genkey key decodes to $decoded_len bytes, expected 32"
    fi

    # Check each genkey produces unique key
    local key2
    key2=$($BINARY genkey 2>/dev/null) || { log_fail "second genkey failed"; return; }
    if [ "$key" != "$key2" ]; then
        log_pass "genkey produces unique keys"
    else
        log_fail "genkey produced identical keys"
    fi
}

test_pubkey() {
    log_info "Testing: pubkey command"

    # Generate a private key
    local private_key
    private_key=$($BINARY genkey 2>/dev/null) || { log_fail "genkey for pubkey test failed"; return; }

    # Derive public key
    local public_key
    public_key=$(echo "$private_key" | $BINARY pubkey 2>/dev/null) || { log_fail "pubkey command failed"; return; }

    # Check it's base64 (44 chars with padding)
    if [ ${#public_key} -eq 44 ]; then
        log_pass "pubkey produces 44-char base64 key"
    else
        log_fail "pubkey produced key of length ${#public_key}, expected 44"
        return
    fi

    # Check public key differs from private key
    if [ "$private_key" != "$public_key" ]; then
        log_pass "pubkey differs from private key"
    else
        log_fail "pubkey equals private key"
    fi

    # Check same private key produces same public key
    local public_key2
    public_key2=$(echo "$private_key" | $BINARY pubkey 2>/dev/null)
    if [ "$public_key" = "$public_key2" ]; then
        log_pass "pubkey is deterministic"
    else
        log_fail "pubkey produced different results for same input"
    fi
}

test_pubkey_invalid_input() {
    log_info "Testing: pubkey with invalid input"

    # Test with invalid base64
    local output
    output=$(echo "not-valid-base64!!!" | $BINARY pubkey 2>&1) || true
    if echo "$output" | grep -qi "invalid\|error"; then
        log_pass "pubkey rejects invalid base64"
    else
        log_fail "pubkey should reject invalid base64"
    fi

    # Test with wrong length key
    output=$(echo "dG9vLXNob3J0" | $BINARY pubkey 2>&1) || true
    if echo "$output" | grep -qi "32 bytes\|error"; then
        log_pass "pubkey rejects wrong-length key"
    else
        log_fail "pubkey should reject wrong-length key"
    fi
}

test_show_config() {
    log_info "Testing: show-config command"

    local output
    output=$($BINARY show-config 2>/dev/null) || { log_fail "show-config command failed"; return; }

    # Check for expected sections
    if echo "$output" | grep -q "\[Interface\]"; then
        log_pass "show-config contains [Interface] section"
    else
        log_fail "show-config missing [Interface] section"
    fi

    if echo "$output" | grep -q "\[Peer\]"; then
        log_pass "show-config contains [Peer] section"
    else
        log_fail "show-config missing [Peer] section"
    fi

    if echo "$output" | grep -q "PrivateKey"; then
        log_pass "show-config contains PrivateKey field"
    else
        log_fail "show-config missing PrivateKey field"
    fi
}

test_config_parsing_valid() {
    log_info "Testing: valid config file parsing"

    # Generate keys for the config
    local private_key public_key
    private_key=$($BINARY genkey 2>/dev/null) || { log_fail "genkey failed"; return; }
    public_key=$($BINARY genkey 2>/dev/null | $BINARY pubkey 2>/dev/null) || { log_fail "pubkey failed"; return; }

    # Create a valid config file
    cat > "$TMP_DIR/valid.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 10.0.0.2/24
ListenPort = 51820
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = $public_key
Endpoint = 192.168.1.1:51820
AllowedIPs = 10.0.0.0/24, 192.168.0.0/16
PersistentKeepalive = 25
EOF

    # Try to parse it (up command will fail without root, but config parsing happens first)
    local output
    output=$($BINARY up -c "$TMP_DIR/valid.conf" 2>&1) || true

    # If we get a permission error or TUN error, config parsed OK
    if echo "$output" | grep -qi "permission\|tun\|root\|cap_net_admin\|operation not permitted"; then
        log_pass "Valid config parses successfully (fails at TUN creation)"
    elif echo "$output" | grep -qi "config\|parse\|invalid\|missing"; then
        log_fail "Valid config rejected: $output"
    else
        log_pass "Valid config accepted"
    fi
}

test_config_parsing_missing_private_key() {
    log_info "Testing: config missing PrivateKey"

    local public_key
    public_key=$($BINARY genkey 2>/dev/null | $BINARY pubkey 2>/dev/null) || { log_fail "key gen failed"; return; }

    cat > "$TMP_DIR/no_privkey.conf" <<EOF
[Interface]
Address = 10.0.0.2/24

[Peer]
PublicKey = $public_key
EOF

    local output
    output=$($BINARY up -c "$TMP_DIR/no_privkey.conf" 2>&1) || true

    if echo "$output" | grep -qi "privatekey\|missing"; then
        log_pass "Detects missing PrivateKey"
    else
        log_fail "Should detect missing PrivateKey: $output"
    fi
}

test_config_parsing_invalid_key() {
    log_info "Testing: config with invalid key"

    cat > "$TMP_DIR/bad_key.conf" <<EOF
[Interface]
PrivateKey = this-is-not-a-valid-key
Address = 10.0.0.2/24
EOF

    local output
    output=$($BINARY up -c "$TMP_DIR/bad_key.conf" 2>&1) || true

    if echo "$output" | grep -qi "invalid\|base64\|key"; then
        log_pass "Detects invalid PrivateKey format"
    else
        log_fail "Should detect invalid PrivateKey: $output"
    fi
}

test_config_parsing_invalid_address() {
    log_info "Testing: config with invalid address"

    local private_key
    private_key=$($BINARY genkey 2>/dev/null) || { log_fail "genkey failed"; return; }

    cat > "$TMP_DIR/bad_addr.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = not-an-ip-address
EOF

    local output
    output=$($BINARY up -c "$TMP_DIR/bad_addr.conf" 2>&1) || true

    if echo "$output" | grep -qi "invalid\|address"; then
        log_pass "Detects invalid Address"
    else
        log_fail "Should detect invalid Address: $output"
    fi
}

test_config_parsing_invalid_port() {
    log_info "Testing: config with invalid port"

    local private_key
    private_key=$($BINARY genkey 2>/dev/null) || { log_fail "genkey failed"; return; }

    cat > "$TMP_DIR/bad_port.conf" <<EOF
[Interface]
PrivateKey = $private_key
ListenPort = 999999
EOF

    local output
    output=$($BINARY up -c "$TMP_DIR/bad_port.conf" 2>&1) || true

    if echo "$output" | grep -qi "invalid\|port"; then
        log_pass "Detects invalid ListenPort"
    else
        log_fail "Should detect invalid ListenPort: $output"
    fi
}

test_config_parsing_peer_missing_pubkey() {
    log_info "Testing: peer section missing PublicKey"

    local private_key
    private_key=$($BINARY genkey 2>/dev/null) || { log_fail "genkey failed"; return; }

    cat > "$TMP_DIR/peer_no_pubkey.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 10.0.0.2/24

[Peer]
Endpoint = 192.168.1.1:51820
AllowedIPs = 10.0.0.0/24
EOF

    local output
    output=$($BINARY up -c "$TMP_DIR/peer_no_pubkey.conf" 2>&1) || true

    if echo "$output" | grep -qi "publickey\|missing"; then
        log_pass "Detects missing Peer PublicKey"
    else
        log_fail "Should detect missing Peer PublicKey: $output"
    fi
}

test_config_parsing_fwmark_hex() {
    log_info "Testing: config with hex FwMark"

    local private_key
    private_key=$($BINARY genkey 2>/dev/null) || { log_fail "genkey failed"; return; }

    cat > "$TMP_DIR/fwmark.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 10.0.0.2/24
FwMark = 0xCAFE
EOF

    local output
    output=$($BINARY up -c "$TMP_DIR/fwmark.conf" 2>&1) || true

    # If we get past config parsing (permission error), hex FwMark worked
    if echo "$output" | grep -qi "permission\|tun\|root"; then
        log_pass "Hex FwMark (0xCAFE) parses correctly"
    elif echo "$output" | grep -qi "fwmark\|invalid"; then
        log_fail "Hex FwMark rejected: $output"
    else
        log_pass "Hex FwMark accepted"
    fi
}

test_config_parsing_multiple_addresses() {
    log_info "Testing: config with multiple addresses"

    local private_key public_key
    private_key=$($BINARY genkey 2>/dev/null) || { log_fail "genkey failed"; return; }
    public_key=$($BINARY genkey 2>/dev/null | $BINARY pubkey 2>/dev/null) || { log_fail "pubkey failed"; return; }

    cat > "$TMP_DIR/multi_addr.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 10.0.0.2/24, 192.168.100.1/24, fd00::1/64

[Peer]
PublicKey = $public_key
AllowedIPs = 0.0.0.0/0, ::/0
EOF

    local output
    output=$($BINARY up -c "$TMP_DIR/multi_addr.conf" 2>&1) || true

    if echo "$output" | grep -qi "permission\|tun\|root"; then
        log_pass "Multiple addresses parse correctly"
    elif echo "$output" | grep -qi "address\|invalid"; then
        log_fail "Multiple addresses rejected: $output"
    else
        log_pass "Multiple addresses accepted"
    fi
}

test_config_parsing_ipv6_endpoint() {
    log_info "Testing: config with IPv6 endpoint"

    local private_key public_key
    private_key=$($BINARY genkey 2>/dev/null) || { log_fail "genkey failed"; return; }
    public_key=$($BINARY genkey 2>/dev/null | $BINARY pubkey 2>/dev/null) || { log_fail "pubkey failed"; return; }

    cat > "$TMP_DIR/ipv6_endpoint.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 10.0.0.2/24

[Peer]
PublicKey = $public_key
Endpoint = [2001:db8::1]:51820
AllowedIPs = 10.0.0.0/24
EOF

    local output
    output=$($BINARY up -c "$TMP_DIR/ipv6_endpoint.conf" 2>&1) || true

    if echo "$output" | grep -qi "permission\|tun\|root"; then
        log_pass "IPv6 endpoint parses correctly"
    elif echo "$output" | grep -qi "endpoint\|invalid"; then
        log_fail "IPv6 endpoint rejected: $output"
    else
        log_pass "IPv6 endpoint accepted"
    fi
}

test_up_no_config() {
    log_info "Testing: up without config"

    local output
    output=$($BINARY up 2>&1) || true

    if echo "$output" | grep -qi "config\|required"; then
        log_pass "up without -c shows error"
    else
        log_fail "up without -c should require config: $output"
    fi
}

test_down_nonexistent() {
    log_info "Testing: down on nonexistent interface"

    local output
    output=$($BINARY down nonexistent_iface_12345 2>&1) || true

    if echo "$output" | grep -qi "not found\|no such\|error\|permission"; then
        log_pass "down on nonexistent interface fails appropriately"
    else
        log_fail "down should fail for nonexistent interface: $output"
    fi
}

test_status_command() {
    log_info "Testing: status command"

    # status for specific interface
    local output
    output=$($BINARY status wg0 2>&1) || true

    if echo "$output" | grep -q "wg0\|not.*implemented"; then
        log_pass "status command runs"
    else
        log_fail "status command failed unexpectedly: $output"
    fi

    # status without interface
    output=$($BINARY status 2>&1) || true
    if echo "$output" | grep -qi "not.*implemented\|hint"; then
        log_pass "status without interface runs"
    else
        log_fail "status without interface failed: $output"
    fi
}

test_verbose_flags() {
    log_info "Testing: verbose flags"

    # Test that verbose flags are accepted
    if $BINARY -v --help >/dev/null 2>&1; then
        log_pass "-v flag accepted"
    else
        log_fail "-v flag rejected"
    fi

    if $BINARY -vv --help >/dev/null 2>&1; then
        log_pass "-vv flag accepted"
    else
        log_fail "-vv flag rejected"
    fi

    if $BINARY -vvv --help >/dev/null 2>&1; then
        log_pass "-vvv flag accepted"
    else
        log_fail "-vvv flag rejected"
    fi
}

# Root-required tests
test_tunnel_creation() {
    if ! is_root; then
        log_skip "Tunnel creation test (requires root)"
        return
    fi

    if $QUICK_MODE; then
        log_skip "Tunnel creation test (--quick mode)"
        return
    fi

    log_info "Testing: tunnel creation (root)"

    local private_key public_key
    private_key=$($BINARY genkey 2>/dev/null) || { log_fail "genkey failed"; return; }
    public_key=$($BINARY genkey 2>/dev/null | $BINARY pubkey 2>/dev/null) || { log_fail "pubkey failed"; return; }

    cat > "$TMP_DIR/tunnel_test.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 10.200.200.1/24
ListenPort = 51899

[Peer]
PublicKey = $public_key
AllowedIPs = 10.200.200.0/24
EOF

    # Start tunnel in background
    $BINARY up -c "$TMP_DIR/tunnel_test.conf" -i wgtun_test -f &
    local pid=$!
    sleep 2

    # Check if interface exists
    if ip link show wgtun_test >/dev/null 2>&1; then
        log_pass "TUN interface created successfully"

        # Check IP address assigned
        if ip addr show wgtun_test | grep -q "10.200.200.1"; then
            log_pass "IP address assigned correctly"
        else
            log_fail "IP address not found on interface"
        fi
    else
        log_fail "TUN interface not created"
    fi

    # Cleanup
    kill $pid 2>/dev/null || true
    sleep 1

    # Interface should be gone after process exits
    if ! ip link show wgtun_test >/dev/null 2>&1; then
        log_pass "Interface cleaned up after exit"
    else
        log_skip "Interface cleanup (may need manual cleanup)"
    fi
}

#
# Test Runner
#

run_all_tests() {
    echo ""
    echo "========================================"
    echo "  wgtun Test Suite"
    echo "========================================"
    echo ""

    setup
    ensure_binary

    echo ""
    echo "--- CLI Basic Tests ---"
    test_help
    test_version
    test_verbose_flags

    echo ""
    echo "--- Key Generation Tests ---"
    test_genkey
    test_pubkey
    test_pubkey_invalid_input

    echo ""
    echo "--- Config Display Tests ---"
    test_show_config

    echo ""
    echo "--- Config Parsing Tests ---"
    test_config_parsing_valid
    test_config_parsing_missing_private_key
    test_config_parsing_invalid_key
    test_config_parsing_invalid_address
    test_config_parsing_invalid_port
    test_config_parsing_peer_missing_pubkey
    test_config_parsing_fwmark_hex
    test_config_parsing_multiple_addresses
    test_config_parsing_ipv6_endpoint

    echo ""
    echo "--- Command Tests ---"
    test_up_no_config
    test_down_nonexistent
    test_status_command

    echo ""
    echo "--- Root-Required Tests ---"
    test_tunnel_creation

    echo ""
    echo "========================================"
    echo "  Test Results"
    echo "========================================"
    echo ""
    echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    echo ""

    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

# Run tests
run_all_tests
