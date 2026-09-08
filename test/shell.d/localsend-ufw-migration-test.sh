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

write_open_rules() {
  cat >"$user_rules" <<'EOF'
-A ufw-user-input -p udp --dport 53317 -j ACCEPT
-A ufw-user-input -p tcp --dport 53317 -j ACCEPT
EOF
  cat >"$user6_rules" <<'EOF'
-A ufw6-user-input -p udp --dport 53317 -j ACCEPT
-A ufw6-user-input -p tcp --dport 53317 -j ACCEPT
EOF
}

write_limited_rules() {
  cat >"$user_rules" <<'EOF'
-A ufw-user-input -p tcp --dport 53317 -s 10.0.0.0/8 -j ACCEPT
-A ufw-user-input -p udp --dport 53317 -s 10.0.0.0/8 -j ACCEPT
-A ufw-user-input -p tcp --dport 53317 -s 172.16.0.0/12 -j ACCEPT
-A ufw-user-input -p udp --dport 53317 -s 172.16.0.0/12 -j ACCEPT
-A ufw-user-input -p tcp --dport 53317 -s 192.168.0.0/16 -j ACCEPT
-A ufw-user-input -p udp --dport 53317 -s 192.168.0.0/16 -j ACCEPT
EOF
  cat >"$user6_rules" <<'EOF'
-A ufw6-user-input -p tcp --dport 53317 -s fe80::/10 -j ACCEPT
-A ufw6-user-input -p udp --dport 53317 -s fe80::/10 -j ACCEPT
-A ufw6-user-input -p tcp --dport 53317 -s fc00::/7 -j ACCEPT
-A ufw6-user-input -p udp --dport 53317 -s fc00::/7 -j ACCEPT
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
grep -q '^sudo bash -s$' "$CALLS" || fail "open rules escalate to rewrite UFW"
grep -q '^ufw --force delete allow 53317/tcp$' "$CALLS" || fail "open rules delete unrestricted TCP"
grep -q '^ufw --force delete allow 53317/udp$' "$CALLS" || fail "open rules delete unrestricted UDP"
grep -q 'ufw allow in proto tcp from 10.0.0.0/8 to any port 53317' "$CALLS" ||
  fail "open rules add RFC1918 TCP"
grep -q 'ufw allow in proto udp from fe80::/10 to any port 53317' "$CALLS" ||
  fail "open rules add IPv6 link-local UDP"
if grep -qE '^ufw allow 53317/' "$CALLS"; then
  fail "open rules do not re-add anywhere-allow" "$(cat "$CALLS")"
fi
pass "open LocalSend UFW rules are rewritten to private CIDRs"

write_limited_rules
run_migration "$test_dir/bin" >/dev/null
if [[ -s $CALLS ]]; then
  fail "already-limited rules do not call sudo or ufw" "$(cat "$CALLS")"
fi
pass "already-limited LocalSend UFW rules are a no-op"

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
