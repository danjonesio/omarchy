#!/bin/bash

set -euo pipefail

source "$(dirname -- "${BASH_SOURCE[0]}")/base-test.sh"

migration="$ROOT/migrations/1788839725.sh"
[[ -f $migration ]] || fail "the LocalSend UFW migration exists at $migration"

test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT

mkdir -p "$test_dir/bin" "$test_dir/failing-bin"

cat >"$test_dir/bin/sudo" <<'STUB'
#!/bin/bash
printf 'sudo %s\n' "$*" >>"$CALLS"
exec "$@"
STUB

cat >"$test_dir/bin/ufw" <<'STUB'
#!/bin/bash
printf 'ufw %s\n' "$*" >>"$CALLS"
STUB

cat >"$test_dir/failing-bin/sudo" <<'STUB'
#!/bin/bash
echo "sudo: a terminal is required to read the password" >&2
exit 1
STUB

cp "$test_dir/bin/ufw" "$test_dir/failing-bin/ufw"
chmod +x "$test_dir/bin/"* "$test_dir/failing-bin/"*

export CALLS="$test_dir/calls"
user_rules="$test_dir/user.rules"
user6_rules="$test_dir/user6.rules"

# Fixtures follow the shape ufw writes to /etc/ufw/user.rules: a "### tuple ###"
# line per rule, then the iptables rule with -p and --dport before -s. The rule
# comment is hex on the tuple line only, never in the iptables rule itself.
# "omarchy-localsend" is 6f6d61726368792d6c6f63616c73656e64.
write_open_rules() {
  cat >"$user_rules" <<'EOF'
*filter
:ufw-user-input - [0:0]
### RULES ###

### tuple ### allow udp 53317 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p udp --dport 53317 -j ACCEPT

### tuple ### allow tcp 53317 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 53317 -j ACCEPT

### END RULES ###
COMMIT
EOF
  cat >"$user6_rules" <<'EOF'
*filter
:ufw6-user-input - [0:0]
### RULES ###

### tuple ### allow udp 53317 ::/0 any ::/0 in
-A ufw6-user-input -p udp --dport 53317 -j ACCEPT

### tuple ### allow tcp 53317 ::/0 any ::/0 in
-A ufw6-user-input -p tcp --dport 53317 -j ACCEPT

### END RULES ###
COMMIT
EOF
}

write_limited_rules() {
  cat >"$user_rules" <<'EOF'
*filter
:ufw-user-input - [0:0]
### RULES ###

### tuple ### allow udp 53317 0.0.0.0/0 any 10.0.0.0/8 in comment=6f6d61726368792d6c6f63616c73656e64
-A ufw-user-input -p udp --dport 53317 -s 10.0.0.0/8 -j ACCEPT

### tuple ### allow tcp 53317 0.0.0.0/0 any 10.0.0.0/8 in comment=6f6d61726368792d6c6f63616c73656e64
-A ufw-user-input -p tcp --dport 53317 -s 10.0.0.0/8 -j ACCEPT

### tuple ### allow udp 53317 0.0.0.0/0 any 172.16.0.0/12 in comment=6f6d61726368792d6c6f63616c73656e64
-A ufw-user-input -p udp --dport 53317 -s 172.16.0.0/12 -j ACCEPT

### tuple ### allow tcp 53317 0.0.0.0/0 any 172.16.0.0/12 in comment=6f6d61726368792d6c6f63616c73656e64
-A ufw-user-input -p tcp --dport 53317 -s 172.16.0.0/12 -j ACCEPT

### tuple ### allow udp 53317 0.0.0.0/0 any 192.168.0.0/16 in comment=6f6d61726368792d6c6f63616c73656e64
-A ufw-user-input -p udp --dport 53317 -s 192.168.0.0/16 -j ACCEPT

### tuple ### allow tcp 53317 0.0.0.0/0 any 192.168.0.0/16 in comment=6f6d61726368792d6c6f63616c73656e64
-A ufw-user-input -p tcp --dport 53317 -s 192.168.0.0/16 -j ACCEPT

### END RULES ###
COMMIT
EOF
  cat >"$user6_rules" <<'EOF'
*filter
:ufw6-user-input - [0:0]
### RULES ###

### tuple ### allow udp 53317 ::/0 any fe80::/10 in comment=6f6d61726368792d6c6f63616c73656e64
-A ufw6-user-input -p udp --dport 53317 -s fe80::/10 -j ACCEPT

### tuple ### allow tcp 53317 ::/0 any fe80::/10 in comment=6f6d61726368792d6c6f63616c73656e64
-A ufw6-user-input -p tcp --dport 53317 -s fe80::/10 -j ACCEPT

### tuple ### allow udp 53317 ::/0 any fc00::/7 in comment=6f6d61726368792d6c6f63616c73656e64
-A ufw6-user-input -p udp --dport 53317 -s fc00::/7 -j ACCEPT

### tuple ### allow tcp 53317 ::/0 any fc00::/7 in comment=6f6d61726368792d6c6f63616c73656e64
-A ufw6-user-input -p tcp --dport 53317 -s fc00::/7 -j ACCEPT

### END RULES ###
COMMIT
EOF
}

run_migration() {
  local path=$1
  : >"$CALLS"
  OMARCHY_UFW_USER_RULES="$user_rules" \
    OMARCHY_UFW_USER6_RULES="$user6_rules" \
    PATH="$path:$ROOT/bin:$PATH" \
    bash -euo pipefail "$migration"
}

write_open_rules
run_migration "$test_dir/bin" >/dev/null
# The migration only reaches for sudo when it is not already root, so a suite
# running as root exercises the rewrite but not the escalation.
if (( EUID == 0 )); then
  pass "running as root; skipping the sudo escalation check"
else
  grep -q '^sudo bash -s$' "$CALLS" || fail "open rules escalate to rewrite UFW"
fi
grep -q '^ufw --force delete allow 53317/tcp$' "$CALLS" || fail "open rules delete unrestricted TCP"
grep -q '^ufw --force delete allow 53317/udp$' "$CALLS" || fail "open rules delete unrestricted UDP"
for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fe80::/10 fc00::/7; do
  grep -q "^ufw allow in proto udp from $cidr to any port 53317 " "$CALLS" ||
    fail "open rules add UDP from $cidr"
  grep -q "^ufw allow in proto tcp from $cidr to any port 53317 " "$CALLS" ||
    fail "open rules add TCP from $cidr"
done
if grep -qE '^ufw allow 53317/' "$CALLS"; then
  fail "open rules do not re-add anywhere-allow" "$(cat "$CALLS")"
fi
grep -q '^ufw reload$' "$CALLS" || fail "open rules reload UFW"
pass "open LocalSend UFW rules are rewritten to private CIDRs"

write_limited_rules
run_migration "$test_dir/bin" >/dev/null
if [[ -s $CALLS ]]; then
  fail "already-limited rules do not call sudo or ufw" "$(cat "$CALLS")"
fi
pass "already-limited LocalSend UFW rules are a no-op"

if (( EUID == 0 )); then
  pass "running as root; skipping the missing-privileges check, which needs sudo to be consulted"
  exit 0
fi

write_open_rules
if PATH="$test_dir/failing-bin:$ROOT/bin:$PATH" \
  OMARCHY_UFW_USER_RULES="$user_rules" \
  OMARCHY_UFW_USER6_RULES="$user6_rules" \
  bash -euo pipefail "$migration" >/dev/null 2>"$test_dir/err"; then
  fail "missing privileges leave the migration pending"
fi
grep -q 'Administrator privileges are required' "$test_dir/err" ||
  fail "missing privileges explain how to retry" "$(cat "$test_dir/err")"
pass "missing privileges leave the LocalSend UFW migration pending"
