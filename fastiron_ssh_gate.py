#!/usr/bin/env python3
# Copyright: (c) 2026, Glitch Works, LLC
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Emulates what a FastIron switch's SSH server does before login.

Listens on a switch's own port and passes connections through to the
emulator's sshd. Models with ssh_refusal_seconds (see MODELS in
fastiron_emulator.py) refuse new connections for that long after accepting
one: the switch reads the client's version line and closes, which libssh
reports as "Socket error: disconnected". Refused connections don't extend
the wait.

    fastiron_ssh_gate.py STATE_FILE LISTEN_PORT SSHD_PORT
"""
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastiron_emulator import model  # noqa: E402

HOST = '127.0.0.1'


class Gate:
    def __init__(self, state_file, sshd_port):
        self.state_file = state_file
        self.sshd_port = sshd_port
        self.last_accepted = None

    def refusal_seconds(self):
        # Read each time, so a test can change the state of a running switch.
        with open(self.state_file) as f:
            return float(model(json.load(f))['ssh_refusal_seconds'])

    def refused(self):
        now = time.monotonic()
        window = self.refusal_seconds()
        if window and self.last_accepted is not None and now - self.last_accepted < window:
            return True
        self.last_accepted = now
        return False

    async def handle(self, reader, writer):
        try:
            if self.refused():
                await asyncio.wait_for(reader.readline(), timeout=5)
                return
            up_reader, up_writer = await asyncio.open_connection(HOST, self.sshd_port)
            await asyncio.gather(pipe(reader, up_writer), pipe(up_reader, writer))
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        try:
            writer.write_eof()
        except OSError:
            pass


async def main():
    if len(sys.argv) != 4:
        raise SystemExit(__doc__.strip().splitlines()[-1].strip())
    state_file, listen_port, sshd_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    gate = Gate(state_file, sshd_port)
    server = await asyncio.start_server(gate.handle, HOST, listen_port)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
