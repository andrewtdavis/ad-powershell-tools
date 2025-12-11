#!/usr/bin/env bash
# AD / FreeIPA trust and connectivity validator
#
# - Discovers DCs via _ldap._tcp.dc._msdcs.<domain>
# - Discovers GCs via _ldap._tcp.gc._msdcs.<forest root> (if forests provided)
# - Tests TCP connectivity to common AD ports
# - Optional DNS functional test via each DC's DNS service
# - Optional MS-RPC functional test via rpcclient (if AD creds + rpcclient)
# - Optional Kerberos TGT test via kinit (if creds or keytab)
# - Optional SSSD GC/DC view via sssctl
#
# Domains and forests are provided via:
#   --domains "d1,d2,..."   or  DOMAINS env var (REQUIRED)
#   --forests "f1,f2,..."   or  FORESTS env var (OPTIONAL)

set -o errexit
set -o nounset
set -o pipefail
trap 'echo; echo "Interrupted by user, exiting."; exit 130' INT TERM

# -------------------- CONFIG --------------------

COMMON_TCP_PORTS=(53 88 135 389 445 464 636)
GC_TCP_PORTS=(3268 3269)

TCP_TIMEOUT=3
UDP_TIMEOUT=2  # currently only used for DNS tools, not generic UDP probes

# Optional AD creds for rpcclient (MS-RPC functional test)
AD_USER="${AD_USER:-}"
AD_PASS="${AD_PASS:-}"

# Optional Kerberos principal for kinit test
KRB_PRINC="${KRB_PRINC:-}"
KRB_PASS="${KRB_PASS:-}"

# Optional credential files (two-line format):
#   line 1: SamAccountName@DomainName
#   line 2: password
AD_CRED_FILE="${AD_CRED_FILE:-}"
KRB_CRED_FILE="${KRB_CRED_FILE:-}"
CRED_FILE="${CRED_FILE:-}"   # common file for both AD and KRB, if specific ones are not set

# Will be filled after parsing flags/env
DOMAINS_STR="${DOMAINS:-}"
FORESTS_STR="${FORESTS:-}"

# -------------------- FUNCTIONS --------------------

have_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<'EOF'
Usage: ad_trust_check.sh [OPTIONS]

Validate connectivity and basic functionality between this host (FreeIPA/SSSD)
and one or more Active Directory domains / forests.

OPTIONS:
  --domains "d1,d2,..."    Comma- or space-separated list of AD DNS domains
                           to test DCs for. REQUIRED unless DOMAINS env var
                           is set.

  --forests "f1,f2,..."    Comma- or space-separated list of AD forest roots
                           for GC discovery (GC SRV records only exist in
                           the forest root).
                           OPTIONAL; if omitted, GC checks are skipped.

  --cred-file PATH         Common credential file used for BOTH AD (rpcclient)
                           and Kerberos (kinit) if more specific files are
                           not provided.
                           Format:
                              line 1: SamAccountName@DomainName
                              line 2: password

  --ad-cred-file PATH      File containing AD credentials for MS-RPC tests.
                           Same format as --cred-file.
                           Takes precedence over --cred-file for AD.

  --krb-cred-file PATH     File containing Kerberos credentials for kinit test.
                           Same format as --cred-file.
                           Takes precedence over --cred-file for Kerberos.

  -h, --help               Show this help and exit.

ENVIRONMENT:
  DOMAINS                  Domains to test (same format as --domains). REQUIRED
                           if --domains is not used.

  FORESTS                  Forest roots to test (same format as --forests).
                           OPTIONAL; if not set, GC section is skipped.

  CRED_FILE                Common credential file for both AD and Kerberos.
                           Same semantics as --cred-file.

  AD_CRED_FILE             Default AD cred file if --ad-cred-file not used.
  KRB_CRED_FILE            Default Kerberos cred file if --krb-cred-file not used.

  AD_USER, AD_PASS         Override AD username/password (for rpcclient).
  KRB_PRINC, KRB_PASS      Override Kerberos principal/password (for kinit).

PRECEDENCE (from highest to lowest):
  * AD_USER / AD_PASS or KRB_PRINC / KRB_PASS env vars
  * --ad-cred-file / AD_CRED_FILE and --krb-cred-file / KRB_CRED_FILE
  * --cred-file / CRED_FILE (used for both AD and KRB)

CREDENTIAL FILE FORMAT (for all cred-file options):
    SamAccountName@DomainName    (line 1)
    password                     (line 2)

This UPN-style form works for both rpcclient and Kerberos kinit.

NOTES:
  * The script requires at least one of: dig or host
    for SRV lookups, and nc or ncat for TCP port checks.

EOF
}

strip_dot() {
  sed 's/\.$//'
}

load_creds_from_file() {
  # $1 = file path, $2 = user/principal var name, $3 = password var name
  local file="$1" user_var="$2" pass_var="$3"
  [ -z "$file" ] && return 0
  if [ ! -r "$file" ]; then
    echo "WARN: credential file '$file' not readable" >&2
    return 1
  fi
  mapfile -t _cred_lines <"$file"
  if [ "${#_cred_lines[@]}" -lt 2 ]; then
    echo "WARN: credential file '$file' must have at least 2 lines (user@domain and password)" >&2
    return 1
  fi
  if [ -z "${!user_var}" ]; then
    printf -v "$user_var" '%s' "${_cred_lines[0]}"
  fi
  if [ -z "${!pass_var}" ]; then
    printf -v "$pass_var" '%s' "${_cred_lines[1]}"
  fi
}

srv_lookup_hosts() {
  # $1 = SRV name; returns unique hostnames
  local srv="$1"
  if have_cmd dig; then
    dig +time=2 +tries=1 +retry=0 +short "$srv" SRV \
      | awk '{print $NF}' | strip_dot | sort -u
  elif have_cmd host; then
    host -t SRV "$srv" 2>/dev/null \
      | awk '/has SRV record/ {print $NF}' | strip_dot | sort -u
  else
    echo "ERROR: need 'dig' or 'host' for SRV lookups" >&2
    return 1
  fi
}

resolve_ips() {
  # $1 = hostname; returns IPs (A/AAAA)
  local h="$1"
  if have_cmd getent; then
    getent ahosts "$h" 2>/dev/null | awk '{print $1}' | sort -u
  elif have_cmd dig; then
    { dig +short A "$h"; dig +short AAAA "$h"; } | sort -u
  else
    getent hosts "$h" 2>/dev/null | awk '{print $1}' | sort -u
  fi
}

tcp_check() {
  # $1 host, $2 port
  local host="$1" port="$2"
  if have_cmd nc; then
    timeout "$TCP_TIMEOUT" nc -z -w "$TCP_TIMEOUT" "$host" "$port" >/dev/null 2>&1
  elif have_cmd ncat; then
    timeout "$TCP_TIMEOUT" ncat -z -w "$TCP_TIMEOUT" "$host" "$port" >/dev/null 2>&1
  else
    return 1
  fi
}

dns_query_via_server() {
  # $1 server IP/host, $2 name to query (A record)
  local server="$1" name="$2"
  if have_cmd dig; then
    # UDP
    if ! timeout "$TCP_TIMEOUT" dig +time=2 +tries=1 @"$server" "$name" A >/dev/null 2>&1; then
      return 1
    fi
    # TCP
    timeout "$TCP_TIMEOUT" dig +time=2 +tries=1 +tcp @"$server" "$name" A >/dev/null 2>&1
  else
    return 0
  fi
}

openssl_tls_probe() {
  # $1 host, $2 port
  local host="$1" port="$2"
  if ! have_cmd openssl; then
    return 1
  fi
  timeout "$TCP_TIMEOUT" openssl s_client -connect "${host}:${port}" -servername "$host" </dev/null >/dev/null 2>&1
}

rpc_functional_test() {
  # Optional MS-RPC test: uses rpcclient with AD_USER/AD_PASS
  local host="$1"
  if ! have_cmd rpcclient; then
    return 1
  fi
  timeout "$TCP_TIMEOUT" rpcclient -U "$AD_USER%$AD_PASS" "$host" -c 'lsaquery; srvinfo' >/dev/null 2>&1
}

kerberos_test() {
  # Optional: attempt a TGT, if creds provided or keytab exists
  if have_cmd kinit; then
    if [ -n "$KRB_PRINC" ] && [ -n "$KRB_PASS" ]; then
      echo "$KRB_PASS" | timeout "$TCP_TIMEOUT" kinit "$KRB_PRINC" >/dev/null 2>&1
      return $?
    elif [ -r /etc/krb5.keytab ]; then
      timeout "$TCP_TIMEOUT" kinit -k >/dev/null 2>&1
      return $?
    fi
  fi
  return 0
}

banner() {
  echo
  echo "========================================"
  echo "$*"
  echo "========================================"
}

show_sssd_gc() {
  local dom="$1"
  if have_cmd sssctl; then
    sssctl domain-status "$dom" --servers || sssctl domain-status "$dom"
  else
    echo "sssctl not available; skipping SSSD GC listing."
  fi
}

check_prereqs() {
  if ! have_cmd dig && ! have_cmd host; then
    echo "ERROR: neither 'dig' nor 'host' is available. Install bind-utils or equivalent." >&2
    exit 1
  fi

  if ! have_cmd nc && ! have_cmd ncat; then
    echo "ERROR: neither 'nc' (netcat) nor 'ncat' is available. Install one of them." >&2
    exit 1
  fi

  if ! have_cmd openssl; then
    echo "WARN: 'openssl' not found; TLS handshake probes (LDAPS/GC-SSL) will be skipped." >&2
  fi
  if ! have_cmd rpcclient; then
    echo "WARN: 'rpcclient' not found; MS-RPC functional tests will be skipped." >&2
  fi
  if ! have_cmd sssctl; then
    echo "WARN: 'sssctl' not found; SSSD domain-status comparison will be skipped." >&2
  fi
  if ! have_cmd kinit; then
    echo "WARN: 'kinit' not found; Kerberos TGT test will be skipped." >&2
  fi
}

# -------------------- ARG PARSING --------------------

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domains)
      shift
      DOMAINS_STR="${1:-}"
      ;;
    --forests)
      shift
      FORESTS_STR="${1:-}"
      ;;
    --cred-file)
      shift
      CRED_FILE="${1:-}"
      ;;
    --ad-cred-file)
      shift
      AD_CRED_FILE="${1:-}"
      ;;
    --krb-cred-file)
      shift
      KRB_CRED_FILE="${1:-}"
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      echo "Try --help for usage." >&2
      exit 1
      ;;
  esac
  shift || true
done

# Resolve domains / forests from flags/env
if [ -z "$DOMAINS_STR" ]; then
  if [ -z "${DOMAINS:-}" ]; then
    echo "ERROR: no domains specified. Use --domains or set DOMAINS env var." >&2
    echo >&2
    usage >&2
    exit 1
  fi
  DOMAINS_STR="$DOMAINS"
fi

# FORESTS_STR is optional; if empty, we just skip GC checks
if [ -z "$FORESTS_STR" ] && [ -n "${FORESTS:-}" ]; then
  FORESTS_STR="$FORESTS"
fi

IFS=', ' read -r -a DOMAINS <<< "$DOMAINS_STR"
if [ -n "$FORESTS_STR" ]; then
  IFS=', ' read -r -a FOREST_ROOTS <<< "$FORESTS_STR"
else
  FOREST_ROOTS=()
fi

# Apply common cred-file to AD/KRB files if those are not already set
if [ -n "$CRED_FILE" ]; then
  if [ -z "$AD_CRED_FILE" ]; then
    AD_CRED_FILE="$CRED_FILE"
  fi
  if [ -z "$KRB_CRED_FILE" ]; then
    KRB_CRED_FILE="$CRED_FILE"
  fi
fi

# Load credentials from files (env vars still win)
load_creds_from_file "$AD_CRED_FILE" AD_USER AD_PASS
load_creds_from_file "$KRB_CRED_FILE" KRB_PRINC KRB_PASS

check_prereqs

# -------------------- MAIN --------------------

FAILS=()
PASS_COUNT=0
FAIL_COUNT=0

echo "Starting AD / FreeIPA trust connectivity validator at $(date)"
echo "Domains:    ${DOMAINS[*]}"
if [ "${#FOREST_ROOTS[@]}" -gt 0 ]; then
  echo "Forest GCs: ${FOREST_ROOTS[*]}"
else
  echo "Forest GCs: (none; GC checks skipped)"
fi
echo "Tools present: $(for t in dig host nc ncat openssl rpcclient sssctl kinit; do have_cmd "$t" && printf "%s " "$t"; done)"
echo

# Kerberos TGT smoke test
if [ -n "${KRB_PRINC:-}" ] || [ -r /etc/krb5.keytab ]; then
  banner "Kerberos TGT test"
  if kerberos_test; then
    echo "OK:   Kerberos TGT acquisition succeeded (password or keytab)."
  else
    echo "WARN: Kerberos TGT test failed; check krb5.conf/realm/time sync."
  fi
fi

# Per-domain DC discovery and tests
for dom in "${DOMAINS[@]}"; do
  banner "Domain: $dom"

  echo "Discovering DCs via _ldap._tcp.dc._msdcs.$dom"
  if ! mapfile -t DC_HOSTS < <(srv_lookup_hosts "_ldap._tcp.dc._msdcs.$dom"); then
    echo "FAIL: SRV lookup failed for $dom"
    FAIL_COUNT=$((FAIL_COUNT+1))
    FAILS+=("SRV lookup failed for $dom")
    continue
  fi

  if [ "${#DC_HOSTS[@]}" -eq 0 ]; then
    echo "FAIL: No DC SRV records found for $dom"
    FAIL_COUNT=$((FAIL_COUNT+1))
    FAILS+=("No DC SRV for $dom")
    continue
  fi
  echo "Discovered DCs: ${DC_HOSTS[*]}"

  for dchost in "${DC_HOSTS[@]}"; do
    echo "- DC host: $dchost"
    mapfile -t IPs < <(resolve_ips "$dchost")
    [ "${#IPs[@]}" -gt 0 ] && echo "  IPs: ${IPs[*]}"

    # DNS functional test via DC's DNS
    if [ "${#IPs[@]}" -gt 0 ]; then
      if dns_query_via_server "${IPs[0]}" "$dchost"; then
        echo "  OK:   DNS via $dchost (UDP+TCP) answered queries."
      else
        echo "  WARN: DNS queries via $dchost failed; check firewall or DNS policy."
      fi
    fi

    # TCP port checks
    for p in "${COMMON_TCP_PORTS[@]}"; do
      if tcp_check "$dchost" "$p"; then
        echo "  OK:   TCP $p reachable"
        PASS_COUNT=$((PASS_COUNT+1))
      else
        echo "  FAIL: TCP $p unreachable"
        FAIL_COUNT=$((FAIL_COUNT+1))
        FAILS+=("$dchost: TCP $p")
      fi
      if [ "$p" = "636" ] && openssl_tls_probe "$dchost" "$p"; then
        echo "  OK:   LDAPS TLS handshake"
      fi
    done

    # Optional MS-RPC functional test
    if [ -n "${AD_USER:-}" ] && [ -n "${AD_PASS:-}" ] && have_cmd rpcclient; then
      if rpc_functional_test "$dchost"; then
        echo "  OK:   MS-RPC lsaquery/srvinfo succeeded (endpoint mapper + dynamic RPC)."
      else
        echo "  WARN: MS-RPC test failed; could be creds/ACLs or firewall on dynamic RPC ports."
      fi
    fi
  done

  # SSSD view of this domain, if available
  if have_cmd sssctl; then
    echo
    echo "SSSD domain-status for $dom:"
    show_sssd_gc "$dom"
  fi
done

# Forest-wide GC discovery and checks (optional)
if [ "${#FOREST_ROOTS[@]}" -gt 0 ]; then
  for root in "${FOREST_ROOTS[@]}"; do
    banner "Forest root GC: $root"
    echo "Discovering GCs via _ldap._tcp.gc._msdcs.$root"
    if ! mapfile -t GC_HOSTS < <(srv_lookup_hosts "_ldap._tcp.gc._msdcs.$root"); then
      echo "FAIL: GC SRV lookup failed for $root"
      FAIL_COUNT=$((FAIL_COUNT+1))
      FAILS+=("GC SRV lookup failed for $root")
      continue
    fi

    if [ "${#GC_HOSTS[@]}" -eq 0 ]; then
      echo "FAIL: No GC SRV records found for $root"
      FAIL_COUNT=$((FAIL_COUNT+1))
      FAILS+=("No GC SRV for $root")
      continue
    fi
    echo "Discovered GCs: ${GC_HOSTS[*]}"

    for gchost in "${GC_HOSTS[@]}"; do
      echo "- GC host: $gchost"
      mapfile -t IPs < <(resolve_ips "$gchost")
      [ "${#IPs[@]}" -gt 0 ] && echo "  IPs: ${IPs[*]}"

      for p in "${GC_TCP_PORTS[@]}"; do
        if tcp_check "$gchost" "$p"; then
          echo "  OK:   TCP $p reachable"
          PASS_COUNT=$((PASS_COUNT+1))
        else
          echo "  FAIL: TCP $p unreachable"
          FAIL_COUNT=$((FAIL_COUNT+1))
          FAILS+=("$gchost: TCP $p")
        fi
        if openssl_tls_probe "$gchost" "$p"; then
          echo "  OK:   GC TLS handshake on $p"
        fi
      done
    done
  done
fi

banner "Summary"
echo "PASS checks: $PASS_COUNT"
echo "FAIL checks: $FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "Failures:"
  for f in "${FAILS[@]}"; do
    echo "  - $f"
  done
fi

echo "Finished at $(date)"
exit 0