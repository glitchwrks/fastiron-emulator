#!/usr/bin/env python3
# Copyright: (c) 2026, Glitch Works, LLC
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Minimal FastIron 08.0.30 CLI emulator, for end-to-end tests of Ansible
content that manages FastIron switches.

Run by sshd as a ForceCommand, one switch per login account. Its behavior
follows sessions captured from ICX 6650s; see the README for what it does
and doesn't emulate.

The switch's state (running configuration, canned "show" output, test hooks)
is the JSON file named by FI_STATE, and changes persist there, so separate
sessions see them. FI_AUTHORIZED_KEYS names the authorized_keys file that an
SCP upload of sshPubKey replaces.

A state's "model" picks the hardware's behavior, from MODELS; the default is
an ICX 6650. Behavior that happens before login, such as refusing
connections, is up to fastiron_ssh_gate.py, which reads MODELS too.
"""
import base64
import json
import os
import re
import struct
import sys
import time

STATE = os.environ.get('FI_STATE', 'fi_state.json')
AUTHORIZED_KEYS = os.environ.get('FI_AUTHORIZED_KEYS', 'authorized_keys')
KEY_BLOCK_RE = re.compile(r'---- BEGIN SSH2 PUBLIC KEY ----([\s\S]*?)---- END SSH2 PUBLIC KEY ----')
OPENERS = {'vlan', 'cluster', 'lag', 'interface'}

# What differs between the emulated models, from captured sessions.
#   ssh_refusal_seconds: after accepting an SSH connection, the switch drops
#     any new one for this long, during key exchange, whether the first is
#     still open or not. Refused connections don't extend the wait. 0 for none.
#   factory_name: the prompt's name before a hostname is set, or None where
#     it hasn't been captured (the emulator then shows "Router").
#   lag_name_quotes: whether LAG names are shown quoted, lag "name" ...
#   lag_member_names: whether deploying a LAG moves its ports' names into the
#     LAG, as "port-name NAME ethernet PORT", and drops its secondary ports'
#     interface blocks (they run at the primary port's settings).
MODELS = {
    'ICX6650': {'ssh_refusal_seconds': 0, 'factory_name': 'ICX6650-64 Router',
                'lag_name_quotes': True, 'lag_member_names': False},
    # Measured on an ICX6610-48P running 08.0.30uT7f3: refused for 13 seconds
    # after the last accepted connection in one test, and 40 to 45 seconds,
    # steadily over three minutes, in a later one, after many failed logins.
    # The longer, so tests cover the worst seen.
    # It also shows LAG names unquoted, and moves deployed LAGs' port names
    # into the LAG.
    'ICX6610': {'ssh_refusal_seconds': 45, 'factory_name': None,
                'lag_name_quotes': False, 'lag_member_names': True},
}
DEFAULT_MODEL = 'ICX6650'

# Global settings that are on by default: turning one off shows "no ..." in
# the running configuration, as captured from the switches.
DEFAULT_ON = {'telnet server', 'web-management http'}


def model(state):
    """The behavior of a state's model; a state's own keys override it."""
    name = state.get('model', DEFAULT_MODEL)
    if name not in MODELS:
        raise SystemExit('unknown model %r, expected one of %s' % (name, ', '.join(sorted(MODELS))))
    behavior = dict(MODELS[name])
    behavior.update({key: state[key] for key in behavior if key in state})
    return behavior


def out(text=''):
    sys.stdout.write(text.replace('\n', '\r\n'))
    sys.stdout.flush()


PAGER = '--More--, next page: Space, next line: Return key, quit: Control-c'
PAGE_LINES = 23


def read_key():
    """Read one key without echo, as the switch's pager does."""
    import termios
    import tty
    fd = sys.stdin.fileno()
    if not os.isatty(fd):
        return sys.stdin.read(1)
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        attrs = termios.tcgetattr(fd)
        attrs[3] &= ~termios.ISIG  # deliver Control-C as a key
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        return os.read(fd, 1).decode('latin-1')
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def out_paged(text, paging):
    """Write lines as FastIron does with page display on: after each page,
    the pager text, then on Space it is erased with backspaces and output
    continues on the same line; Return shows one more line; Control-C stops."""
    if not paging:
        out(text)
        return
    lines = text.split('\n')
    shown = 0
    budget = PAGE_LINES
    for i, line in enumerate(lines):
        last = i == len(lines) - 1
        sys.stdout.write(line + ('' if last else '\r\n'))
        if last:
            break
        shown += 1
        if shown >= budget and i < len(lines) - 2:
            sys.stdout.write(PAGER)
            sys.stdout.flush()
            key = read_key()
            if key == '\x03':
                sys.stdout.write('^C\r\n')
                sys.stdout.flush()
                return
            sys.stdout.write('\x08 \x08' * len(PAGER))
            shown = 0
            budget = PAGE_LINES if key == ' ' else 1
    sys.stdout.flush()


def load():
    with open(STATE) as f:
        return json.load(f)


def save(state):
    with open(STATE, 'w') as f:
        json.dump(state, f)


def auth_method():
    """'publickey' or 'password', from sshd's ExposeAuthInfo file."""
    path = os.environ.get('SSH_USER_AUTH')
    if path and os.path.exists(path):
        with open(path) as f:
            text = f.read()
        if text.startswith('publickey') or '\npublickey' in text:
            return 'publickey'
    return 'password'


def write_authorized_keys(key_file):
    lines = []
    for block in KEY_BLOCK_RE.findall(key_file):
        body = ''.join(line.strip() for line in block.splitlines() if ':' not in line)
        blob = base64.b64decode(body)
        key_type = blob[4:4 + struct.unpack('>I', blob[:4])[0]].decode()
        lines.append('%s %s' % (key_type, body))
    with open(AUTHORIZED_KEYS, 'w') as f:
        f.write('\n'.join(lines) + '\n')


def scp(command):
    """Minimal SCP endpoint, as strict as FastIron: the target must be exactly
    sshPubKey, without shell quoting, and an upload replaces the key list."""
    words = command.split()
    target = words[-1]
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    if '-f' in words:
        stdout.write(b'\x01scp: %s: No such file or directory\n' % target.encode())
        stdout.flush()
        return 1
    stdout.write(b'\0')
    stdout.flush()
    header = stdin.readline().decode()
    if target != 'sshPubKey':
        # FastIron accepts the request, then refuses the file.
        stdout.write(b'\x01Wrong file name is specified\n')
        stdout.flush()
        return 1
    size = int(header.split()[1])
    stdout.write(b'\0')
    stdout.flush()
    data = stdin.read(size)
    stdin.read(1)
    state = load()
    state['pubkey_file'] = data.decode()
    save(state)
    write_authorized_keys(state['pubkey_file'])
    if state.get('scp_disconnect'):
        # Drop the whole SSH connection instead of acknowledging the file.
        import signal
        os.kill(os.getppid(), signal.SIGKILL)
    stdout.write(b'\0')
    stdout.flush()
    return 0


def show_who(method):
    """Laid out as FastIron prints it, with tabs between the fields."""
    user = '' if method == 'publickey' else ', user is %s' % os.environ.get('USER', 'admin')
    return ('Console connections:\n\testablished, privilege super-user\n'
            '\t3 hours 5 minutes 37 seconds in idle\n'
            'Telnet server status: Disabled\n'
            'SSH server status: Enabled\nSSH connections:\nSSH connections (inbound):\n'
            ' 1\testablished, client ip address 10.0.0.1, server hostkey RSA, user is admin, privilege super-user\n'
            '\tusing vrf default-vrf.\n'
            '\t31 minutes 39 seconds in idle\n'
            ' 2\testablished, client ip address 10.0.0.1, server hostkey RSA%s, privilege super-user\n'
            '\tusing vrf default-vrf.\n'
            '\tyou are connecting to this session\n'
            ' 3\tclosed\n' % user)


def parse_ports(words):
    """"ethe 1/1/2 ethe 1/1/7 to 1/1/8" -> ['1/1/2', '1/1/7', '1/1/8']"""
    ports, i = [], 0
    while i < len(words):
        w = words[i]
        if re.match(r'^\d+(/\d+)*$', w):
            if i + 2 < len(words) and words[i + 1] == 'to':
                a, b = w.split('/'), words[i + 2].split('/')
                ports.extend('/'.join(a[:-1] + [str(n)]) for n in range(int(a[-1]), int(b[-1]) + 1))
                i += 3
                continue
            ports.append(w)
        i += 1
    return ports


def port_key(port):
    return tuple(int(x) for x in port.split('/'))


def format_ports(ports, keyword='ethe'):
    key = port_key
    runs = []
    for port in sorted(set(ports), key=key):
        if runs and key(port)[:-1] == key(runs[-1][-1])[:-1] and key(port)[-1] == key(runs[-1][-1])[-1] + 1:
            runs[-1].append(port)
        else:
            runs.append([port])
    return ' '.join('%s %s' % (keyword, r[0]) if len(r) == 1 else '%s %s to %s' % (keyword, r[0], r[-1])
                    for r in runs)


def vlan_ports(node, kind):
    line = next((c for c in node if c[0].split()[0] == kind), None)
    return parse_ports(line[0].split()[1:]) if line else []


def set_vlan_ports(node, kind, ports):
    node[:] = [c for c in node if c[0].split()[0] != kind]
    if ports:
        # tagged first, then untagged, then everything else, as FastIron shows them
        position = 0 if kind == 'tagged' else sum(1 for c in node if c[0].startswith('tagged '))
        node.insert(position, ['%s %s' % (kind, format_ports(ports)), []])


def parse(text):
    """Config text -> list of [line, children] trees."""
    root = []
    stack = [(-1, root)]
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.strip() == '!' or line.startswith(('Current configuration', 'ver ', 'end')):
            continue
        indent = len(line) - len(line.lstrip())
        while stack[-1][0] >= indent:
            stack.pop()
        node = [line.strip(), []]
        stack[-1][1].append(node)
        stack.append((indent, node[1]))
    return root


def render(tree, depth=0):
    lines = []
    for text, children in tree:
        if depth == 0 and text.startswith('ip ssh '):
            # FastIron prints these with two spaces after "ip ssh".
            text = 'ip ssh  ' + text[len('ip ssh '):].lstrip()
        lines.append(' ' * depth + text)
        lines.extend(render(children, depth + 1))
        if depth == 0:
            lines.append('!')
    return lines


def find(tree, path):
    node = tree
    for text in path:
        node = next(c[1] for c in node if c[0] == text)
    return node


def mode_name(path):
    if not path:
        return 'config'
    head = path[0].split()
    if head[0] == 'vlan':
        name = 'config-vlan-%s' % head[1]
    elif head[0] == 'cluster':
        name = 'config-cluster-%s' % head[1]
    elif head[0] == 'lag':
        name = 'config-lag-%s' % head[1].strip('"')
    elif head[0] == 'interface':
        name = 'config-if-e10000-%s' % head[-1]
    else:
        name = 'config-%s' % head[0]
    if len(path) > 1 and path[1].startswith('client '):
        name += '-client-%s' % path[1].split()[1]
    return name


def cluster_deployed(node):
    return any(c[0] == 'deploy' for c in node)


def keep_alive_locked(tree, vid):
    """Whether VLAN vid is the keep-alive VLAN of a deployed cluster."""
    for text, children in tree:
        if text.startswith('cluster ') and cluster_deployed(children) and any(
                c[0] == 'keep-alive-vlan %s' % vid for c in children):
            return True
    return False


def deployed_lags(tree):
    """[(id, primary port, member ports)] of the deployed LAGs."""
    lags = []
    for text, children in tree:
        if text.startswith('lag ') and any(c[0] == 'deploy' for c in children):
            words = text.split()
            lag_id = words[words.index('id') + 1] if 'id' in words else '?'
            members = [p for c in children if c[0].startswith('ports ') for p in parse_ports(c[0].split()[1:])]
            primary = next((c[0].split()[1] for c in children if c[0].startswith('primary-port ')), members[0])
            lags.append((lag_id, primary, members))
    return lags


def lag_name(text):
    return text.split()[1].strip('"')


def lag_members(children):
    members = [p for c in children if c[0].startswith('ports ') for p in parse_ports(c[0].split()[1:])]
    primary = next((c[0].split()[1] for c in children if c[0].startswith('primary-port ')),
                   members[0] if members else None)
    return primary, members


def move_member_names(tree, lag):
    """What an ICX 6610 does on deploy: its ports' names go into the LAG, and the
    secondary ports' interface blocks are dropped."""
    primary, members = lag_members(lag[1])
    for port in members:
        block = next((c for c in tree if c[0] == 'interface ethernet %s' % port), None)
        if block is None:
            continue
        name = next((c[0].split(None, 1)[1] for c in block[1] if c[0].startswith('port-name ')), None)
        if name is not None:
            set_lag_port_name(lag[1], port, name)
        if port != primary:
            tree.remove(block)


def set_lag_port_name(children, port, name):
    line = 'port-name %s ethernet %s' % (name, port)
    for child in children:
        if child[0].startswith('port-name ') and child[0].split()[-1] == port:
            child[0] = line
            return
    children.append([line, []])


def main():
    original = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    if original.startswith('scp '):
        sys.exit(scp(original))
    state = load()
    tree = parse(state['running'])
    method = auth_method()
    if method != 'publickey' and any(t == 'ip ssh password-authentication no' for t, _ in tree):
        out('Permission denied (password authentication is disabled).\n')
        return
    privileged = False
    paging = True
    config_path = None  # None = EXEC mode; [] = global config; [...] = sub-mode

    def hostname():
        for text, _ in tree:
            if text.startswith('hostname '):
                return text.split()[1]
        return model(state)['factory_name'] or 'Router'

    def prompt():
        if config_path is None:
            return 'SSH@%s%s' % (hostname(), '#' if privileged else '>')
        return 'SSH@%s(%s)#' % (hostname(), mode_name(config_path))

    def commit():
        state['running'] = '\n'.join(render(tree))
        save(state)

    out(prompt())
    while True:
        line = sys.stdin.readline()
        if not line:
            return
        cmd = line.strip()
        words = cmd.split()
        out('\n')
        if not cmd:
            pass
        elif cmd == state.get('fail_on'):
            # Test hook: make one command fail, as the switch reports errors.
            out('Error - simulated failure of %s\n' % cmd)
        elif config_path is None:
            if cmd in ('ena', 'enable'):
                if privileged:
                    pass
                elif state.get('enable_password'):
                    out('Password:')
                    answer = sys.stdin.readline().strip()
                    out('\n')
                    if answer == state['enable_password']:
                        privileged = True
                    else:
                        out('Error - Incorrect username or password.\n')
                else:
                    out('No password has been assigned yet...\n')
                    privileged = True
            elif cmd in ('skip', 'skip-page-display') and privileged:
                paging = False
                out('Disable page display mode\n')
            elif cmd == 'show who':
                out(show_who(method))
            elif cmd == 'show ip client-pub-key':
                out(load().get('pubkey_file', ''))
            elif cmd in ('show interface brief', 'show interfaces brief', 'sh inter brie'):
                out(state.get('show_interface_brief', '') + '\n')
            elif cmd in ('show cluster', 'show clust'):
                out(state.get('show_cluster', '') + '\n')
            elif cmd == 'show version':
                out(state['version'])
            elif cmd in ('show running-config', 'show configuration'):
                config = '\n'.join(render(tree))
                out_paged('Current configuration:\n!\nver 08.0.30uT323\n!\n%s\nend\n\n' % config, paging)
            elif cmd in ('conf ter', 'configure terminal') and privileged:
                config_path = []
            elif cmd in ('wri mem', 'write memory') and privileged:
                out('Write startup-config done.\n\n')
                out(prompt())
                time.sleep(float(state.get('flash_delay', 1.5)))
                out('Flash Memory Write (8192 bytes per dot) .\nFlash to Flash Done.\n')
                state['writes'] = state.get('writes', 0) + 1
                save(state)
                continue
            elif cmd in ('exit', 'logout', 'quit'):
                return
            else:
                out('Invalid input -> %s\nType ? for a list\n' % cmd)
        else:
            if cmd == 'end':
                config_path = None
            elif cmd == 'exit':
                config_path = config_path[:-1] if config_path else None
            elif words[0] == 'bogus':
                out('Invalid input -> %s\nType ? for a list\n' % cmd)
            elif not config_path and words[0] == 'vlan' and len(words) > 1 and words[1].isdigit():
                # VLANs are entered by number; "name" renames an existing one
                name = words[words.index('name') + 1] if 'name' in words else None
                existing = next((c for c in tree if c[0].split()[:2] == ['vlan', words[1]]), None)
                if existing is None:
                    existing = ['vlan %s%s by port' % (words[1], ' name %s' % name if name else ''), []]
                    tree.append(existing)
                elif name:
                    existing[0] = 'vlan %s name %s by port' % (words[1], name)
                commit()
                config_path = [existing[0]]
            elif config_path and config_path[0].startswith('vlan ') and len(config_path) == 1 and (
                    words[0] in ('tagged', 'untagged') or words[:2] in (['no', 'tagged'], ['no', 'untagged'])):
                node = find(tree, config_path)
                remove = words[0] == 'no'
                kind = words[1] if remove else words[0]
                ports = parse_ports(words[2:] if remove else words[1:])
                vid = config_path[0].split()[1]
                current = vlan_ports(node, kind)
                lags = deployed_lags(tree)
                secondary = next(((lag_id, p) for p in ports for lag_id, primary, members in lags
                                  if p in members and p != primary), None)
                if keep_alive_locked(tree, vid):
                    out('Error - vlan %s is a cluster keep alive VLAN.  Can not be modified while cluster is active\n'
                        % vid)
                elif remove and secondary:
                    out('Error - Vlan %s Operation on Lag %s Secondary port %s is not Allowed.\n'
                        % (vid, secondary[0], secondary[1]))
                else:
                    for lag_id, primary, members in lags:
                        if primary in ports:
                            ports = ports + [p for p in members if p not in ports]
                    if remove:
                        set_vlan_ports(node, kind, [p for p in current if p not in ports])
                    else:
                        set_vlan_ports(node, kind, current + [p for p in ports if p not in current])
                        out('Added %s port(s) %s to port-vlan %s.\n' % (kind, format_ports(ports), vid))
                    commit()
            elif (config_path and config_path[0].startswith('cluster ') and len(config_path) == 1
                  and words[0] in ('keep-alive-vlan', 'session-vlan', 'no') and words[-1] != 'deploy'
                  and cluster_deployed(find(tree, config_path))):
                out('Error - Change not permitted because cluster %s is deployed\n' % config_path[0].split()[2])
            elif config_path and config_path[0].startswith('cluster ') and len(config_path) == 1 and cmd == 'deploy':
                node = find(tree, config_path)
                if not cluster_deployed(node):
                    clients = [i for i, c in enumerate(node) if c[0].startswith('client ')]
                    node.insert(clients[0] if clients else len(node), ['deploy', []])
                    commit()
            elif not config_path and (' '.join(words[1:]) in DEFAULT_ON and words[0] == 'no'
                                      or ' '.join(words) in DEFAULT_ON):
                setting = ' '.join(words[1:]) if words[0] == 'no' else ' '.join(words)
                tree[:] = [c for c in tree if c[0] not in (setting, 'no ' + setting)]
                if words[0] == 'no':
                    tree.append(['no ' + setting, []])
                commit()
            elif words[0] == 'no' and len(words) > 1:
                node = find(tree, config_path)
                node[:] = [c for c in node if c[0] != ' '.join(words[1:])]
                commit()
            elif (config_path and config_path[0].startswith('lag ') and len(config_path) == 1
                  and words[0] == 'port-name' and len(words) > 3 and words[-2].startswith('ethe')):
                lag = next(c for c in tree if c[0] == config_path[0])
                set_lag_port_name(lag[1], words[-1], ' '.join(words[1:-2]))
                commit()
            else:
                if words[0] == 'lag' and len(words) > 1 and not config_path:
                    # The same LAG, however its name is quoted, shown as the model shows it.
                    existing = next((c for c in tree if c[0].startswith('lag ') and lag_name(c[0]) == lag_name(cmd)),
                                    None)
                    if existing is not None:
                        cmd = existing[0]
                    else:
                        name = lag_name(cmd)
                        rest = cmd.split(None, 2)[2] if len(words) > 2 else ''
                        cmd = ('lag "%s" %s' if model(state)['lag_name_quotes'] else 'lag %s %s') % (name, rest)
                    words = cmd.split()
                if words[:2] == ['enable', 'super-user-password'] and not config_path:
                    state['enable_password'] = words[2]
                    cmd = 'enable super-user-password .....'
                    words = cmd.split()
                node = find(tree, config_path)
                existing = next((c for c in node if ' '.join(c[0].split()) == ' '.join(cmd.split())), None)
                if existing is None:
                    # a new hostname replaces the old one
                    if words[0] == 'hostname':
                        node[:] = [c for c in node if not c[0].startswith('hostname ')]
                    node.append([cmd, []])
                    commit()
                if (cmd == 'deploy' and config_path and config_path[0].startswith('lag ') and len(config_path) == 1
                        and model(state)['lag_member_names']):
                    move_member_names(tree, next(c for c in tree if c[0] == config_path[0]))
                    commit()
                opens = words[0] in OPENERS if not config_path else (
                    config_path[0].startswith('cluster ') and words[0] == 'client' and len(config_path) == 1)
                if opens:
                    config_path = config_path + [cmd]
            state.setdefault('log', []).append(cmd)
            save(state)
        out(prompt())


if __name__ == '__main__':
    main()
