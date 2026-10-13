# anon

A Bash learning project for inspecting Tor-observed egress and running explicit network diagnostics on an SSH server. It retains the original Nipe + SSH concept with input validation, verified SSH host keys, bounded requests, and honest status reporting.

**Status: maintained learning project; offline regression tests pass. Live Nipe, firewall, SSH and scan workflows have not been validated by this update.**

A changed IP or country does not establish anonymity. A positive Tor Project response describes **one HTTPS request**, not every application or connection.

## What changed

- Removed country-based anonymity claims, password collection, `sshpass`, and disabled SSH host-key checking.
- Added separate `setup`, `status`, and `run` commands, plus help and an offline dry run.
- Require valid Tor-observed egress before opening the diagnostic SSH session. Failed or malformed lookups are **unknown**, not success.
- Take a validated, explicit scan target. No local `eth0` address is inserted into a remote command.
- Use SSH keys/agent or OpenSSH's own password prompt, with `StrictHostKeyChecking=yes`.
- Preserve existing Nipe/Tor/firewall state by never invoking Nipe `install`, `start`, `stop`, or `restart`.

## Why Nipe lifecycle is manual

The [Nipe revision](https://github.com/htrgouvea/nipe/tree/08d37038d17a61eddb89ba73328c8d105c7dc199) whose lifecycle modules were inspected has significant global effects:

- [`Start.pm`](https://github.com/htrgouvea/nipe/blob/08d37038d17a61eddb89ba73328c8d105c7dc199/lib/Nipe/Component/Engine/Start.pm) calls `Stop` before starting and modifies IPv4/IPv6 OUTPUT chains.
- [`Stop.pm`](https://github.com/htrgouvea/nipe/blob/08d37038d17a61eddb89ba73328c8d105c7dc199/lib/Nipe/Component/Engine/Stop.pm) flushes OUTPUT rules in the filter/nat tables and stops Tor. It cannot distinguish rules this wrapper owns from pre-existing rules.
- [`Install.pm`](https://github.com/htrgouvea/nipe/blob/08d37038d17a61eddb89ba73328c8d105c7dc199/lib/Nipe/Network/Install.pm) also calls `Stop`.
- [`Status.pm`](https://github.com/htrgouvea/nipe/blob/08d37038d17a61eddb89ba73328c8d105c7dc199/lib/Nipe/Component/Utils/Status.pm) queries the Tor Project API. It is an egress observation, **not** proof that a particular local service is running. The Nipe CLI may return exit code zero for an error message.

Consequently, this wrapper does not attempt automatic firewall restoration or stop a pre-existing Tor session. Prepare and manage Nipe separately in a disposable Linux lab after reviewing its source and the lab's networking. Do not treat this wrapper as a privacy guarantee.

## Requirements

| Operation | Local requirements |
| --- | --- |
| Help | Bash and basic Unix tools |
| `run --dry-run` | Python 3 |
| `status` | Python 3 and curl with HTTPS support |
| `run` | Python 3, curl, OpenSSH client, verified server host key, working SSH account, and egress observed as Tor by the Tor Project |
| `setup` | Git, Perl 5.30+, and the modules declared by the pinned Nipe `cpanfile` |

The SSH host needs a POSIX shell, Python 3, curl, WHOIS, Nmap, and a `timeout` command. The fixed Nmap TCP-connect scan does not require root. Run this wrapper as your normal SSH user; it does not require `sudo`.

## Usage

```bash
bash anon.sh --help

# Optional: download reviewed Nipe source and check Perl module imports.
# The destination's parent directory must already exist.
bash anon.sh setup --nipe-dir "$HOME/tools/nipe"

# After configuring egress separately:
bash anon.sh status

# Validate the plan without performing any network request or SSH connection.
bash anon.sh run --host 192.0.2.10 --user analyst \
  --target 198.51.100.20 --dry-run

# Execute in an authorized lab, using real lab addresses and verified host keys.
bash anon.sh run --host 192.0.2.10 --user analyst \
  --target 198.51.100.20 \
  --identity "$HOME/.ssh/lab_ed25519" \
  --known-hosts "$HOME/.ssh/known_hosts"
```

The example addresses are documentation placeholders. Replace them with your SSH server and authorized diagnostic target. `--port PORT` selects a non-default SSH port.

Targets may be IPv4 addresses, aligned IPv4 CIDRs (for example `192.0.2.0/24`), or single IPv6 addresses. DNS scan targets, arbitrary Nmap flags, malformed IPs, IPv6 networks, and shell expressions are rejected. The displayed CIDR is the entire authorized scan scope; review it before running.

### Setup behavior

The pin reflects an inspection of the lifecycle/status modules, not a complete security audit of Nipe or its dependencies.

The default checkout path is `nipe` beside `anon.sh`. Setup downloads the official repository, checks out commit `08d37038d17a61eddb89ba73328c8d105c7dc199`, and checks Perl module imports. It does not run package managers, CPAN, or Nipe code. Import checks verify availability, not every version constraint or platform requirement.

A matching clean checkout is reused. A different origin/revision, local changes, or a non-checkout directory causes a failure without overwriting it. A failed download removes only the destination created by that invocation. A successful checkout is retained when dependencies are missing so you can review its `cpanfile` and install the required packages separately. Setup does not automatically update the pin.

### Status and routing scope

`status` uses `https://check.torproject.org/api/ip`, validates the JSON `IP` and boolean `IsTor`, and reports both. The local request has a 5-second connection timeout and 15-second total timeout. Curl configuration and proxy environment settings are bypassed for this observation so it uses host routing, as Nipe does.

| Exit code | Meaning |
| --- | --- |
| `0` | Tor exit observed for the status request, or requested command completed |
| `1` | Invalid arguments, missing dependency, lookup/parse failure, or another local error |
| `2` | Status request succeeded but the source was not observed as a Tor exit; `run` did not open SSH |
| Other nonzero | SSH/remote command failure, timeout, or interruption (for example `255` from SSH or `143` for SIGTERM) |

There is no country comparison and no claim that the IP changed: the wrapper does not start Nipe, so it cannot produce a meaningful before/after-start measurement. Tor exit observation also does not identify which local service supplied the route. Nipe may exclude local destinations; an SSH connection to a private lab address may take a different path from the HTTPS check.

### SSH and remote actions

An unknown or changed SSH host key is rejected. Verify the server's fingerprint through a trusted channel and provision the correct `known_hosts` entry first. The wrapper does not automatically accept keys or treat `ssh-keyscan` output alone as trusted.

The SSH client ignores user/system SSH configuration (`-F /dev/null`) to keep this invocation predictable, disables agent forwarding and configured forwardings, and preserves native key/agent/password authentication. Specify the host, port, identity and known-hosts file explicitly when needed. Known-hosts paths containing quoting/control characters or OpenSSH expansion tokens are rejected; shell-expanded `$HOME` paths work. SSH config aliases, ProxyJump and ProxyCommand are not supported by this wrapper.

After the local egress check, one SSH session:

1. Verifies remote dependencies.
2. Reads and validates the remote host's public IP over HTTPS from `api.ipify.org`.
3. Performs WHOIS on that IP (30-second limit).
4. Runs a TCP-connect scan of **ports 22, 80, and 443** against the explicit target, with DNS resolution disabled, at most two probe retries, a 60-second per-host timeout and a 180-second total command limit. IPv6 targets use `-6`.

A failed step stops subsequent steps and propagates a nonzero result. These are deliberately bounded diagnostics; a timeout or limited port scan is not evidence that no other services exist. The remote public IP and remote scan use the **remote host's** network configuration; local Tor egress does not imply that remote traffic uses Tor.

On interruption, the wrapper terminates its own SSH child (with a forced-kill fallback after approximately two seconds) and removes only an incomplete setup directory it created. It never stops Tor/Nipe or alters firewall rules. Abrupt termination of the SSH client cannot guarantee immediate cancellation of every remote process; remote commands have their own time bounds.

## Offline validation

```bash
bash -n anon.sh
python3 -m unittest discover -s tests -v
```

The regression suite stubs curl, SSH, Git, Perl, and privileged/network tools. It covers invalid and injected input, help/dry-run isolation, malformed/unavailable/non-Tor status results, SSH options and failure propagation, IPv4/IPv6 handling, pinned/idempotent setup, and failure cleanup. It does not install software, alter networking, scan hosts, or attempt authentication.
