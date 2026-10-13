# anon

A Bash learning project that combines Nipe setup, a public-IP country comparison, and interactive SSH-based diagnostics.

## Current status

The repository contains a single script, [anon.sh](anon.sh). It passes a Bash syntax check, but its networking and SSH workflows have not been run as part of this documentation review.

**A changed country code does not prove anonymity.** The script's "You are anonymous" message reflects a simple WHOIS comparison, not a verified privacy or traffic-routing guarantee.

## What the script does

1. Requests the current public IP from `ifconfig.me` and extracts a country field from WHOIS output.
2. Checks whether the local user is root.
3. Clones the Nipe repository into the current working directory, installs Perl dependencies, and invokes Nipe installation and startup.
4. Repeats the public-IP/WHOIS lookup and compares the country result with the earlier value.
5. If the values differ, prompts for a server address, SSH username, and password.
6. Opens two SSH sessions: one invokes Nmap on the remote host, and the other looks up the remote host's public IP with WHOIS.

This script installs software and changes local networking through Nipe. It also performs remote commands.

## Requirements

For the local workflow, the script expects:

- A Linux environment with Bash and root access.
- `curl`, `whois`, `git`, `sudo`, Perl/`cpan`, `ssh`, `sshpass`, and `ip`.
- Common text utilities such as `grep`, `awk`, and `uniq`.
- Internet access to the Nipe repository, Perl dependencies, and public-IP/WHOIS services.

The SSH server is expected to provide Nmap, `curl`, and `whois`. Nipe may have additional platform requirements; the wrapper does not validate them.

## Usage

Review [anon.sh](anon.sh) before running it in a disposable, authorized lab environment:

```bash
sudo bash anon.sh
```

The script is interactive and provides no command-line flags or help mode. Its country check determines whether the SSH prompts are reached.

## Known limitations

- **The country comparison is not a routing check:** lookup failures, empty results, or inconsistent WHOIS fields can produce misleading conclusions.
- **SSH host verification is disabled:** connections use `StrictHostKeyChecking=no`.
- **Password handling needs improvement:** the prompt does not hide input, and the password is supplied through `sshpass -p`.
- **The scan target is selected locally:** the `ip a` command is expanded before SSH runs. It uses the local `eth0` address/prefix, not an interface discovered on the SSH server.
- **Installation failures are not checked:** a failed clone, directory change, dependency installation, or Nipe startup may not stop subsequent steps.
- **Repeated runs are fragile:** an existing `nipe` directory is not handled explicitly.
- **There is no automatic cleanup:** the script does not stop Nipe or restore networking when it exits.
- Public-IP requests have no explicit timeout, and inputs are not validated.
- The script assumes a local interface named `eth0`.

## Potential improvements

- Replace the anonymity claim with explicit routing/status checks and clear failure states.
- Prefer SSH keys and verified host keys; remove password handling from the wrapper.
- Make the intended diagnostic target explicit and validate it.
- Separate dependency setup from normal execution.
- Check command results and add predictable cleanup and logging.

These are review proposals only; the script has not been changed.
