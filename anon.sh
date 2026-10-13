#!/usr/bin/env bash
# Author: Martin Osher
# Inspect observed egress and run explicit diagnostics through verified SSH.
set -Eeuo pipefail
umask 077

readonly NIPE_URL='https://github.com/htrgouvea/nipe.git'
readonly NIPE_COMMIT='08d37038d17a61eddb89ba73328c8d105c7dc199'
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
nipe_dir="$SCRIPT_DIR/nipe"
mode=''
ssh_host=''
ssh_user=''
ssh_port=22
identity=''
known_hosts=''
target=''
family=''
dry_run=0
owned_setup_dir=''
ssh_pid=''

usage() {
    cat <<'HELP'
Usage:
  bash anon.sh status
  bash anon.sh setup [--nipe-dir PATH]
  bash anon.sh run --host HOST --user USER --target IP_OR_CIDR [OPTIONS]

Commands:
  status  Report the public IP and Tor Project's result for one HTTPS request.
          Returns 0 for Tor-observed egress, 2 for non-Tor, 1 for unknown/error.
  setup   Fetch a pinned Nipe checkout and check its Perl dependencies.
          Does NOT install packages or invoke Nipe install/start/stop.
  run     Require Tor-observed egress, then run remote public-IP/WHOIS and
          an explicit TCP-connect Nmap diagnostic through verified SSH.

Options for run:
  --host HOST          SSH server: IP address or DNS name (not a shell command).
  --user USER          SSH account; use keys/ssh-agent or SSH's own password prompt.
  --target IP_OR_CIDR   Authorized IPv4 address/network, or single IPv6 address.
  --port PORT          SSH port (default: 22).
  --identity PATH      Readable private-key file (optional).
  --known-hosts PATH   Readable file of independently verified host keys (optional).
  --dry-run            Validate and display the plan without network access.
  -h, --help           Show this help without network access.

Examples:
  bash anon.sh setup --nipe-dir "$HOME/tools/nipe"
  bash anon.sh status
  bash anon.sh run --host 192.0.2.10 --user analyst --target 198.51.100.20 --dry-run

Nipe lifecycle is managed separately: upstream start/install/stop can flush
existing OUTPUT firewall rules. This wrapper never starts or stops Nipe/Tor.
A Tor observation, changed IP or country does not establish anonymity or prove
that SSH, DNS, another application, or traffic from the remote host uses Tor.
HELP
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }
need_value() { (( $# >= 2 )) && [[ -n $2 && $2 != --* ]] || die "Missing value for $1"; }

cleanup() {
    local rc=$?
    trap - EXIT INT TERM HUP
    if [[ -n $ssh_pid ]]; then
        kill -TERM -- "$ssh_pid" 2>/dev/null || true
        # Bound shutdown even if a stuck child ignores TERM.
        local attempt
        for attempt in {1..20}; do
            kill -0 -- "$ssh_pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL -- "$ssh_pid" 2>/dev/null || true
        wait "$ssh_pid" 2>/dev/null || true
    fi
    # Only remove the setup directory this process created and has not completed.
    if [[ -n $owned_setup_dir ]]; then
        rm -rf -- "$owned_setup_dir"
    fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

validate_inputs() {
    need python3
    [[ -n $ssh_host && -n $ssh_user && -n $target ]] || die 'run requires --host, --user and --target.'
    [[ $ssh_user =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$ ]] || die 'Invalid SSH username.'
    [[ $ssh_port =~ ^[0-9]{1,5}$ ]] && (( 10#$ssh_port >= 1 && 10#$ssh_port <= 65535 )) || die 'SSH port must be 1-65535.'
    ssh_port=$((10#$ssh_port))
    python3 - "$ssh_host" <<'PY' || die 'Invalid SSH host.'
import ipaddress, re, sys
host = sys.argv[1]
try:
    ipaddress.ip_address(host)
    if '%' in host:
        raise ValueError('zone IDs are not supported')
except ValueError:
    labels = host.rstrip('.').split('.')
    if len(host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x) for x in labels):
        sys.exit(1)
    # Invalid numeric-looking IPs must not fall back to being accepted as DNS.
    if re.fullmatch(r'[0-9.]+', host):
        sys.exit(1)
PY
    local normalized
    normalized=$(python3 - "$target" <<'PY'
import ipaddress, sys
try:
    value = sys.argv[1]
    if '%' in value:
        raise ValueError('zone IDs are not supported')
    if '/' in value:
        ip = ipaddress.ip_network(value, strict=True)
        if ip.version != 4:
            raise ValueError('IPv6 networks are not supported; use one IPv6 address')
    else:
        ip = ipaddress.ip_address(value)
    print(str(ip), ip.version)
except ValueError as error:
    print(error, file=sys.stderr)
    sys.exit(1)
PY
    ) || die 'Invalid target: use an IPv4 address/aligned CIDR or one IPv6 address.'
    read -r target family <<< "$normalized"
    [[ -z $identity || -f $identity && -r $identity ]] || die 'Identity file is not readable.'
    [[ -z $known_hosts || -f $known_hosts && -r $known_hosts ]] || die 'Known-hosts file is not readable.'
    if [[ -n $known_hosts ]]; then
        [[ $known_hosts != *$'\n'* && $known_hosts != *$'\r'* && $known_hosts != *'"'* && $known_hosts != *'\'* && $known_hosts != *'%'* && $known_hosts != *'$'* && $known_hosts != '~'* ]] || die 'Known-hosts path contains unsupported quoting characters.'
    fi
}

status() {
    need curl
    need python3
    local response observation observed_ip tor_seen
    # Ignore curl config and explicit proxy environment settings. Nipe uses host routing.
    response=$(curl --disable --fail --silent --show-error --noproxy '*' \
        --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 15 \
        'https://check.torproject.org/api/ip') || {
        printf 'Egress observation: UNKNOWN (HTTPS request failed).\n' >&2
        return 1
    }
    observation=$(python3 -c '
import ipaddress, json, sys
try:
    data = json.load(sys.stdin)
    if not isinstance(data["IP"], str):
        raise ValueError("IP must be a string")
    ip = ipaddress.ip_address(data["IP"])
    seen = data["IsTor"]
    if type(seen) is not bool or "%" in str(ip):
        raise ValueError("invalid response fields")
    print(ip, "true" if seen else "false")
except (ValueError, TypeError, KeyError):
    sys.exit(1)
' <<< "$response") || {
        printf 'Egress observation: UNKNOWN (invalid Tor Project response).\n' >&2
        return 1
    }
    read -r observed_ip tor_seen <<< "$observation"
    printf 'Observed public IP: %s\nTor exit observed for this HTTPS request: %s\n' "$observed_ip" "$tor_seen"
    printf 'This does not verify Nipe service state, all traffic routing, or anonymity.\n'
    [[ $tor_seen == true ]] || return 2
}

setup() {
    need git
    need perl
    [[ $nipe_dir = /* ]] || nipe_dir="$PWD/$nipe_dir"
    if [[ -e $nipe_dir || -L $nipe_dir ]]; then
        [[ -d $nipe_dir/.git && ! -L $nipe_dir ]] || die 'Existing Nipe path is not a regular Git checkout.'
        local origin head changes
        origin=$(git -C "$nipe_dir" remote get-url origin) || die 'Could not read checkout origin.'
        head=$(git -C "$nipe_dir" rev-parse HEAD) || die 'Could not read checkout revision.'
        changes=$(git -C "$nipe_dir" status --porcelain) || die 'Could not inspect checkout changes.'
        [[ $origin == "$NIPE_URL" ]] || die 'Existing checkout has a different origin; leaving it unchanged.'
        [[ $head == "$NIPE_COMMIT" ]] || die 'Existing checkout is not the reviewed commit; leaving it unchanged.'
        [[ -z $changes ]] || die 'Existing checkout has local changes; leaving it unchanged.'
        printf 'Reusing reviewed Nipe checkout: %s\n' "$nipe_dir"
    else
        # Reserve an otherwise absent path; never overwrite a user's checkout.
        mkdir -- "$nipe_dir" || die 'Could not create Nipe directory; create its parent first.'
        owned_setup_dir=$nipe_dir
        git clone --no-checkout -- "$NIPE_URL" "$nipe_dir" || die 'Nipe download failed.'
        git -C "$nipe_dir" checkout --detach "$NIPE_COMMIT" || die 'Could not select the reviewed Nipe commit.'
        [[ $(git -C "$nipe_dir" rev-parse HEAD) == "$NIPE_COMMIT" ]] || die 'Downloaded commit verification failed.'
        owned_setup_dir=''
    fi
    # Read-only import checks; no CPAN, package manager, nipe.pl, or firewall commands.
    perl -MIO::Socket::SSL -MJSON -MTry::Tiny -MConfig::Simple -MReadonly -MHTTP::Tiny \
        -e 'use 5.030; print "Perl dependency imports passed.\n";' || \
        die 'Perl dependencies are missing. Review the pinned cpanfile and install them separately.'
    printf 'Nipe source ready at: %s\nPinned commit: %s\n' "$nipe_dir" "$NIPE_COMMIT"
    printf 'Package installation and Nipe lifecycle are manual; see README.md before proceeding.\n'
}

run_diagnostics() {
    validate_inputs
    printf 'SSH server: %s@%s:%s\nRemote scan target: %s (IPv%s)\n' "$ssh_user" "$ssh_host" "$ssh_port" "$target" "$family"
    printf 'Remote actions: public-IP lookup, WHOIS, Nmap TCP-connect scan of ports 22,80,443.\n'
    if (( dry_run )); then
        printf 'Dry run: no network requests, SSH, Nipe or firewall commands executed.\n'
        return 0
    fi
    need ssh
    if status; then :; else
        local rc=$?
        printf 'Diagnostics stopped: Tor-observed egress is required; no SSH session opened.\n' >&2
        return "$rc"
    fi
    local -a ssh_args=(-F /dev/null -T -o StrictHostKeyChecking=yes -o ForwardAgent=no
        -o ClearAllForwardings=yes -o ConnectTimeout=10 -o ServerAliveInterval=15
        -o ServerAliveCountMax=2 -p "$ssh_port" -l "$ssh_user")
    [[ -z $identity ]] || ssh_args+=(-i "$identity" -o IdentitiesOnly=yes)
    [[ -z $known_hosts ]] || ssh_args+=(-o "UserKnownHostsFile=\"$known_hosts\"")
    # target/family are normalized IP characters/digits, never arbitrary shell input.
    ssh "${ssh_args[@]}" "$ssh_host" "sh -s -- '$target' '$family'" <<'REMOTE' &
set -eu
for tool in curl python3 whois nmap timeout; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'Missing remote dependency: %s\n' "$tool" >&2; exit 1; }
done
scan_target=$1
family=$2
remote_ip=$(curl --disable --fail --silent --show-error --noproxy '*' \
    --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 15 https://api.ipify.org)
remote_ip=$(printf '%s' "$remote_ip" | python3 -c 'import ipaddress,sys; print(ipaddress.ip_address(sys.stdin.read().strip()))')
printf 'Remote host observed public IP: %s\n' "$remote_ip"
timeout 30 whois "$remote_ip"
printf '\nTCP-connect diagnostic for %s (ports 22,80,443):\n' "$scan_target"
if [ "$family" = 6 ]; then
    timeout 180 nmap -6 -n -sT -p 22,80,443 --max-retries 2 --host-timeout 60s "$scan_target"
else
    timeout 180 nmap -n -sT -p 22,80,443 --max-retries 2 --host-timeout 60s "$scan_target"
fi
REMOTE
    ssh_pid=$!
    local rc=0
    wait "$ssh_pid" || rc=$?
    ssh_pid=''
    if (( rc != 0 )); then
        printf 'Remote diagnostics failed (SSH/remote exit code %s).\n' "$rc" >&2
    fi
    return "$rc"
}

(( $# )) || { usage; exit 1; }
case $1 in
    -h|--help) usage; exit 0 ;;
    setup|status|run) mode=$1; shift ;;
    *) die "Unknown command: $1 (see --help)." ;;
esac
while (( $# )); do
    case $1 in
        -h|--help) usage; exit 0 ;;
        --nipe-dir)
            [[ $mode == setup ]] || die '--nipe-dir applies only to setup.'
            need_value "$@"; nipe_dir=$2; shift 2 ;;
        --host|--user|--port|--target|--identity|--known-hosts)
            [[ $mode == run ]] || die "$1 applies only to run."
            need_value "$@"
            case $1 in
                --host) ssh_host=$2 ;; --user) ssh_user=$2 ;; --port) ssh_port=$2 ;;
                --target) target=$2 ;; --identity) identity=$2 ;; --known-hosts) known_hosts=$2 ;;
            esac
            shift 2 ;;
        --dry-run)
            [[ $mode == run ]] || die '--dry-run applies only to run.'
            dry_run=1; shift ;;
        *) die "Unknown argument: $1" ;;
    esac
done
case $mode in
    setup) setup ;;
    status) status ;;
    run) run_diagnostics ;;
esac
