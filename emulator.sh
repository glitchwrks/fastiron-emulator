#!/bin/sh
# Copyright: (c) 2026, Glitch Works, LLC
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Sets up and runs the FastIron emulator behind its own sshd, one login
# account per switch in states/. Meant for a disposable Linux test machine or
# container, run as root:
#
#   ./emulator.sh setup   create the accounts, keys and sshd configuration,
#                         and copy the switch states in
#   ./emulator.sh start   start sshd (on 127.0.0.1, port FI_PORT), and a gate
#                         for each switch whose state has an ssh_port
#   ./emulator.sh stop    stop them
#   ./emulator.sh reset   copy the switch states in again, undoing changes
#
# Settings, from the environment:
#   FI_RUN_DIR  where everything lives (default /var/lib/fastiron-emulator)
#   FI_PORT     sshd's port (default 2222)

set -eu

repo=$(cd "$(dirname "$0")" && pwd)
run=${FI_RUN_DIR:-/var/lib/fastiron-emulator}
port=${FI_PORT:-2222}
group=fastiron-emu

switches() {
    for state in "$repo"/states/*.json; do
        basename "$state" .json
    done
}

# The switch's own SSH port, if its state has one. Such a switch is reached
# through fastiron_ssh_gate.py, which emulates what its model does before
# login; the others are reached on sshd's port directly.
ssh_port() {
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("ssh_port", ""))' \
        "$repo/states/$1.json"
}

# Each switch's state, with the client key as its SSH key list, as if the key
# had been uploaded to the switch.
reset_states() {
    mkdir -p "$run/state" "$run/keys"
    ssh2_key=$(ssh-keygen -e -f "$run/client_rsa.pub")
    for switch in $(switches); do
        SSH2_KEY=$ssh2_key python3 -c '
import json, os, sys
state = json.load(open(sys.argv[1]))
state["pubkey_file"] = os.environ["SSH2_KEY"] + "\n"
json.dump(state, open(sys.argv[2], "w"), indent=2)
' "$repo/states/$switch.json" "$run/state/$switch.json"
        cp "$run/client_rsa.pub" "$run/keys/$switch"
    done
    chgrp -R "$group" "$run/state" "$run/keys"
    chmod 2775 "$run/state" "$run/keys"
    chmod 664 "$run/state"/*.json "$run/keys"/*
}

setup() {
    getent group "$group" >/dev/null || groupadd "$group"
    for switch in $(switches); do
        if ! getent passwd "$switch" >/dev/null; then
            useradd -m -g "$group" -s /bin/sh "$switch"
        fi
        # Unlocked, but with no password: logins are by key only.
        usermod -p '*' "$switch"
    done

    mkdir -p "$run" /run/sshd
    chmod 755 "$run"
    cp "$repo/fastiron_emulator.py" "$repo/fastiron_ssh_gate.py" "$run/"
    chmod 755 "$run/fastiron_emulator.py" "$run/fastiron_ssh_gate.py"

    # FastIron 08.0.30 only offers RSA host keys and these old algorithms.
    [ -f "$run/host_rsa" ] || ssh-keygen -q -t rsa -b 2048 -N '' -f "$run/host_rsa"
    # The key the tests log in with, in place of the switches' shared key.
    [ -f "$run/client_rsa" ] || ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -f "$run/client_rsa"

    {
        echo "Port $port"
        echo "ListenAddress 127.0.0.1"
        echo "HostKey $run/host_rsa"
        echo "PidFile $run/sshd.pid"
        echo "KexAlgorithms diffie-hellman-group1-sha1"
        echo "HostKeyAlgorithms ssh-rsa"
        echo "Ciphers aes256-cbc"
        echo "MACs hmac-sha1"
        echo "PubkeyAcceptedAlgorithms +ssh-rsa"
        echo "PasswordAuthentication no"
        echo "KbdInteractiveAuthentication no"
        echo "UsePAM no"
        echo "MaxSessions 1"
        echo "StrictModes no"
        echo "ExposeAuthInfo yes"
        echo "AuthorizedKeysFile $run/keys/%u"
        for switch in $(switches); do
            echo "Match User $switch"
            echo "    ForceCommand /usr/bin/env FI_STATE=$run/state/$switch.json" \
                 "FI_AUTHORIZED_KEYS=$run/keys/$switch python3 $run/fastiron_emulator.py"
        done
    } >"$run/sshd_config"

    reset_states
    echo "Set up in $run; log in with $run/client_rsa as one of: $(switches | tr '\n' ' ')"
}

start() {
    /usr/sbin/sshd -f "$run/sshd_config" -E "$run/sshd.log"
    echo "Listening on 127.0.0.1:$port"
    for switch in $(switches); do
        gate_port=$(ssh_port "$switch")
        [ -n "$gate_port" ] || continue
        python3 "$run/fastiron_ssh_gate.py" "$run/state/$switch.json" "$gate_port" "$port" \
            >>"$run/gate-$switch.log" 2>&1 &
        echo $! >"$run/gate-$switch.pid"
        echo "$switch: listening on 127.0.0.1:$gate_port"
    done
}

stop() {
    for pidfile in "$run/sshd.pid" "$run"/gate-*.pid; do
        [ -f "$pidfile" ] || continue
        kill "$(cat "$pidfile")" 2>/dev/null || true
        rm -f "$pidfile"
    done
}

case ${1:-} in
    setup) setup ;;
    start) start ;;
    stop) stop ;;
    reset) reset_states ;;
    *) echo "usage: $0 setup|start|stop|reset" >&2; exit 2 ;;
esac
