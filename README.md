FastIron emulator
=================

A small emulator of the Brocade / Ruckus FastIron 08.0.30 CLI, as seen over SSH on ICX 6650 and ICX 6610 switches, for testing Ansible content that manages them before it touches real switches. It backs the end-to-end tests of [glitchwrks.fastiron](https://github.com/glitchwrks/glitchwrks.fastiron), the FastIron roles in [gw.general](https://github.com/glitchwrks/gw.general), and the playbooks that use them.

It is not a switch simulator. Configuration commands edit a stored running configuration, and the rest of the switch's state, such as `show cluster`, is canned text in a state file that a test sets up. What it does emulate closely is the CLI's behavior where that has tripped up Ansible: prompts, paging, odd output layouts, and the commands FastIron refuses.

What it emulates
----------------

* Logins land at the user EXEC prompt, `SSH@<hostname>>`. `enable` asks for the enable password, or enters privileged EXEC with "No password has been assigned yet..." when there is none.
* Paging: long output stops at a `--More--` prompt after 23 lines, until `skip-page-display`, which only works in privileged EXEC. Space shows the next page, Return one more line, Control-C stops. The pager text is erased with backspaces.
* `write memory` prints its first line and the prompt, and only then the flash progress lines, with no prompt after them.
* Configuration mode with VLAN, LAG, interface, cluster and cluster client sub-modes, and their prompts. VLAN ports are stored and shown as FastIron does: tagged before untagged, ranges as `ethe 1/1/7 to 1/1/8`.
* The refusals of a deployed MCT cluster: its keep-alive VLAN's ports, and its `keep-alive-vlan` and `session-vlan`, can't be changed until `no deploy`.
* Deployed LAGs: VLAN ports are removed through the LAG's primary port, which removes all of its ports. Removing a secondary port is refused.
* `show running-config`, `show version`, `show who` (laid out with tabs, as FastIron does), `show ip client-pub-key`, `show cluster` and `show interface brief`. The last two print canned text from the state file.
* SCP upload of the SSH public key list, as strict as FastIron: the target must be exactly `sshPubKey`. An upload replaces the switch's authorized keys.
* Key logins and password logins are told apart, and password logins are refused when the configuration has `ip ssh password-authentication no`.
* Differences between models, picked by a state's `model`. An ICX 6610 (08.0.30uT7f3) refuses any new SSH connection for about 13 seconds after accepting one, whether that one is still open or not: it reads the client's version line and closes, which libssh reports as `Socket error: disconnected`. Refused connections don't extend the wait. An ICX 6650 accepts connections back to back. The models are in `MODELS` in `fastiron_emulator.py`.

Each error message is the switch's own text, taken from captured sessions.

Running it
----------

It runs behind its own sshd, with one login account per switch, so it needs a disposable Linux machine or container, with Python 3 and an OpenSSH server that still supports the old algorithms FastIron 08.0.30 needs (`diffie-hellman-group1-sha1`, `ssh-rsa`, `aes256-cbc`, `hmac-sha1`). As root:

    ./emulator.sh setup
    ./emulator.sh start

`setup` creates the accounts `cs1a`, `cs1b` and `cs2`, one for each file in `states/`, a host key and a client key, and the sshd configuration, all in `/var/lib/fastiron-emulator` (`FI_RUN_DIR`). sshd listens on 127.0.0.1, port 2222 (`FI_PORT`). A switch whose state has an `ssh_port` is reached on that port instead, through `fastiron_ssh_gate.py`, which `start` runs for it: the gate emulates what the switch's model does before login, and passes connections through to sshd. Run `setup` again after changing the emulator, to install the new version.

`./emulator.sh reset` puts the switches' states back as they are in `states/`, undoing changes made by tests. `./emulator.sh stop` stops sshd and the gates.

`examples/inventory.yml` points glitchwrks.fastiron at the three switches. Log in by hand with:

    ssh -i /var/lib/fastiron-emulator/client_rsa -p 2222 \
        -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa \
        -o PubkeyAcceptedAlgorithms=+ssh-rsa -o Ciphers=+aes256-cbc -o MACs=+hmac-sha1 \
        cs1a@127.0.0.1

The switches
------------

`states/` holds:

* An MCT pair of ICX 6650s, cs1a and cs1b, in a healthy state: cluster ALB-CORE with its ICL on LAG 2 (1/1/7 and 1/1/8), keep-alive VLAN 3001 on its own link (1/1/40), and one client, c2960g, on 1/1/2.
* A single ICX 6610, cs2, on its own port, 2223: an access-layer switch with port names, a dual-mode trunk and a management VE, and the 6610's connection refusals.

Each state file is JSON:

| Key | What it is |
| --- | --- |
| `model` | `ICX6650` (the default) or `ICX6610`: the behavior that differs between models, from `MODELS` in `fastiron_emulator.py`. A state can override a model's value with a key of the same name, such as `ssh_refusal_seconds`. |
| `ssh_port` | Optional: the switch's own port, through `fastiron_ssh_gate.py`. Needed for behavior before login, such as `ssh_refusal_seconds`. |
| `running` | The running configuration, without the `Current configuration` header and `end`. Configuration commands change it. |
| `version` | `show version` output. |
| `show_cluster`, `show_interface_brief` | Canned output of those commands. |
| `enable_password` | The enable password. Set by `enable super-user-password`, too. |
| `pubkey_file` | The SSH public key list, as uploaded by SCP. `setup` and `reset` set it to the client key. |
| `fail_on` | A command that fails with an error, as the switch reports errors. For testing how failures are handled. |
| `scp_disconnect` | When true, an SCP upload drops the SSH connection instead of acknowledging the file. |
| `flash_delay` | Seconds between `write memory`'s prompt and its flash progress lines. Defaults to 1.5. |
| `writes`, `log` | Written by the emulator: the number of `write memory` commands, and the configuration commands received. |

A test sets up a fault by changing the state of the running copy, in `/var/lib/fastiron-emulator/state/`, for example replacing `show_interface_brief` with output where an ICL port is down, then runs `reset` afterwards.

Adding behavior
---------------

Add behavior from what a real switch does, in a captured session, and use the switch's own messages. This repository is public: sanitize anything taken from a real switch, using the placeholders already here: `example.net` host names, 10.0.0.0/24 and 10.0.1.0/24 addresses, `0012.3456.789a`-style MAC addresses, and `XXXXXXXXXXX` for serial and license numbers. No passwords, password hashes or private keys.

License
-------

GNU General Public License v3.0 or later; see `LICENSE`.
