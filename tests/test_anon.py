"""Offline regression tests. External network, SSH and Git commands are stubs."""
import json
import os
from pathlib import Path
import subprocess
import signal
import time
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "anon.sh"
PIN = "08d37038d17a61eddb89ba73328c8d105c7dc199"

STUB = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, signal, time
name = pathlib.Path(sys.argv[0]).name
with open(os.environ['CALL_LOG'], 'a') as handle:
    handle.write(json.dumps([name, *sys.argv[1:]]) + '\n')
if name == 'curl':
    print(os.environ.get('TOR_RESPONSE', '{"IP":"203.0.113.7","IsTor":true}'))
    sys.exit(int(os.environ.get('CURL_EXIT', '0')))
if name == 'ssh':
    pathlib.Path(os.environ['SSH_BODY']).write_text(sys.stdin.read())
    if os.environ.get('SSH_STALL'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        pathlib.Path(os.environ['SSH_PID']).write_text(str(os.getpid()))
        time.sleep(60)
    sys.exit(int(os.environ.get('SSH_EXIT', '0')))
if name == 'git':
    args = sys.argv[1:]
    if 'clone' in args:
        if os.environ.get('CLONE_FAIL'):
            sys.exit(1)
        (pathlib.Path(args[-1]) / '.git').mkdir()
    elif 'get-url' in args:
        print(os.environ.get('GIT_ORIGIN', 'https://github.com/htrgouvea/nipe.git'))
    elif 'rev-parse' in args:
        print(os.environ.get('GIT_HEAD', '08d37038d17a61eddb89ba73328c8d105c7dc199'))
    elif 'status' in args:
        print(os.environ.get('GIT_STATUS', ''))
    sys.exit(0)
if name == 'perl':
    sys.exit(int(os.environ.get('PERL_EXIT', '0')))
# Never let a test accidentally reach an unmocked privileged operation.
sys.exit('Unexpected forbidden command: ' + name)
'''


class AnonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.bin = self.work / 'bin'
        self.bin.mkdir()
        self.log = self.work / 'calls.jsonl'
        self.body = self.work / 'remote.sh'
        for name in ('curl', 'ssh', 'git', 'perl', 'sudo', 'iptables', 'ip6tables', 'systemctl', 'service', 'cpan', 'cpanm', 'nmap', 'whois'):
            executable = self.bin / name
            executable.write_text(STUB)
            executable.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                    'CALL_LOG': str(self.log), 'SSH_BODY': str(self.body)}

    def run_script(self, *args, **env):
        return subprocess.run(['bash', str(SCRIPT), *args], cwd=self.work,
                              env={**self.env, **env}, text=True, capture_output=True, timeout=10)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def run_args(self):
        return ['run', '--host', '192.0.2.10', '--user', 'analyst', '--target', '198.51.100.20']

    def test_help_and_dry_run_are_offline(self):
        self.assertEqual(self.run_script('--help').returncode, 0)
        self.assertEqual(self.run_script(*self.run_args(), '--dry-run').returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_reject_missing_and_injected_input_before_network(self):
        for args in (['run', '--host'], ['run', '--target', '--dry-run'],
                     self.run_args() + ['--target', '1.2.3.4; touch /tmp/unsafe'],
                     self.run_args() + ['--host', 'host;id'],
                     self.run_args() + ['--user', 'user$(id)'],
                     self.run_args() + ['--port', '65536'],
                     self.run_args() + ['--target', '192.0.2.10/24'],
                     self.run_args() + ['--host', '999.999.1.1']):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_script(*args).returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_unknown_status_does_not_open_ssh(self):
        for response in ('', 'not-json', '{}', '[]', '{"IP":"not-ip","IsTor":true}',
                         '{"IP":"203.0.113.7","IsTor":"false"}',
                         '{"IP":5,"IsTor":true}'):
            with self.subTest(response=response):
                self.assertEqual(self.run_script(*self.run_args(), TOR_RESPONSE=response).returncode, 1)
        self.assertTrue(all(call[0] == 'curl' for call in self.calls()))

    def test_network_error_stops_run(self):
        result = self.run_script(*self.run_args(), CURL_EXIT='28')
        self.assertEqual(result.returncode, 1)
        self.assertIn('UNKNOWN', result.stderr)
        self.assertEqual([c[0] for c in self.calls()], ['curl'])

    def test_non_tor_is_distinct_and_no_ssh(self):
        result = self.run_script(*self.run_args(), TOR_RESPONSE='{"IP":"203.0.113.7","IsTor":false}')
        self.assertEqual(result.returncode, 2)
        self.assertIn('false', result.stdout)
        self.assertEqual([c[0] for c in self.calls()], ['curl'])

    def test_verified_run_uses_verified_host_and_explicit_remote_target(self):
        result = self.run_script(*self.run_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([c[0] for c in self.calls()], ['curl', 'ssh'])
        curl, ssh = self.calls()
        self.assertIn('--max-time', curl)
        self.assertIn('StrictHostKeyChecking=yes', ssh)
        self.assertIn('ForwardAgent=no', ssh)
        self.assertEqual(ssh[-1], "sh -s -- '198.51.100.20' '4'")
        self.assertNotIn('sshpass', ' '.join(ssh))
        self.assertIn('nmap -n -sT -p 22,80,443', self.body.read_text())
        syntax = subprocess.run(['sh', '-n', str(self.body)], capture_output=True)
        self.assertEqual(syntax.returncode, 0)

    def test_ssh_failure_is_reported_without_lifecycle_commands(self):
        result = self.run_script(*self.run_args(), SSH_EXIT='255')
        self.assertEqual(result.returncode, 255)
        self.assertIn('failed', result.stderr)
        self.assertEqual([c[0] for c in self.calls()], ['curl', 'ssh'])

    def test_ipv6_address_and_ipv4_network_are_explicit(self):
        for target in ('2001:db8::5', '198.51.100.0/24'):
            with self.subTest(target=target):
                result = self.run_script(*self.run_args(), '--target', target, '--dry-run')
                self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.run_script(*self.run_args(), '--target', '2001:db8::/64', '--dry-run').returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_setup_is_pinned_and_repeated_run_does_not_clone_again(self):
        dest = self.work / 'nipe checkout'
        result = self.run_script('setup', '--nipe-dir', str(dest))
        self.assertEqual(result.returncode, 0, result.stderr)
        second = self.run_script('setup', '--nipe-dir', str(dest))
        self.assertEqual(second.returncode, 0, second.stderr)
        calls = self.calls()
        self.assertEqual(sum('clone' in c for c in calls), 1)
        self.assertTrue(any('checkout' in c and PIN in c for c in calls))
        self.assertTrue(all(c[0] in ('git', 'perl') for c in calls))
        self.assertFalse(any('nipe.pl' in ' '.join(c) for c in calls))

    def test_failed_clone_removes_only_created_checkout(self):
        dest = self.work / 'failed checkout'
        sentinel = self.work / 'keep-me'
        sentinel.write_text('untouched')
        result = self.run_script('setup', '--nipe-dir', str(dest), CLONE_FAIL='1')
        self.assertEqual(result.returncode, 1)
        self.assertFalse(dest.exists())
        self.assertEqual(sentinel.read_text(), 'untouched')

    def test_existing_wrong_checkout_is_preserved(self):
        dest = self.work / 'existing'
        (dest / '.git').mkdir(parents=True)
        sentinel = dest / 'work.txt'
        sentinel.write_text('untouched')
        result = self.run_script('setup', '--nipe-dir', str(dest), GIT_HEAD='different')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(sentinel.read_text(), 'untouched')
        self.assertFalse(any('clone' in c or 'checkout' in c for c in self.calls()))

    def test_interrupt_kills_only_own_stuck_ssh_child(self):
        marker = self.work / 'ssh.pid'
        proc = subprocess.Popen(['bash', str(SCRIPT), *self.run_args()], cwd=self.work,
                                env={**self.env, 'SSH_STALL': '1', 'SSH_PID': str(marker)},
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 3
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(marker.exists())
            child_pid = int(marker.read_text())
            proc.send_signal(signal.SIGTERM)
            proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)
            self.assertEqual([c[0] for c in self.calls()], ['curl', 'ssh'])
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
            if marker.exists():
                try:
                    os.kill(int(marker.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_known_hosts_with_spaces_is_one_quoted_ssh_option(self):
        hosts = self.work / 'known hosts'
        hosts.write_text('stub')
        result = self.run_script(*self.run_args(), '--known-hosts', str(hosts))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('UserKnownHostsFile="' + str(hosts) + '"', self.calls()[-1])

    def test_known_hosts_expansion_tokens_are_rejected(self):
        for name in ('known%hosts', 'known$hosts', 'known\\hosts', 'known"hosts'):
            hosts = self.work / name
            hosts.write_text('stub')
            result = self.run_script(*self.run_args(), '--known-hosts', str(hosts), '--dry-run')
            self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_dependency_failure_keeps_completed_download(self):
        dest = self.work / 'nipe'
        result = self.run_script('setup', '--nipe-dir', str(dest), PERL_EXIT='1')
        self.assertEqual(result.returncode, 1)
        self.assertTrue((dest / '.git').is_dir())
        self.assertIn('dependencies', result.stderr)


if __name__ == '__main__':
    unittest.main()
