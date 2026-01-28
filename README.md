# Private Tor Bridge (obfs4) — Ubuntu/Debian Installer

A hardened, automated installer to set up a **private Tor bridge** using **obfs4** on **Ubuntu/Debian**.

A *private bridge* is **not published** to the public Tor directory. This significantly reduces mass blocking and makes censorship circumvention more resilient.

> This project is intended for legitimate privacy, security, and censorship‑circumvention use. Operate it responsibly and in compliance with local laws and your hosting provider’s policies.

---

## Overview

This repository provides a single installer script that automates the full lifecycle of setting up a private Tor bridge.

The script:
- Installs **Tor**, **obfs4proxy**, and **nyx**
- Adds the **official Tor Project APT repository** with **GPG fingerprint validation**
- Configures Tor as a **private obfs4 bridge**
- Optionally opens required ports via **UFW** (if present)
- Enables and restarts the `tor` systemd service
- Prints a **ready‑to‑paste obfs4 bridge line** including:
  - public server IP
  - transport port
  - bridge fingerprint

---

## Features

- **Private by default**  
  `PublishServerDescriptor 0`

- **Traffic obfuscation**  
  obfs4 pluggable transport

- **Security hardening**  
  - SOCKS proxy disabled (`SocksPort 0`)  
  - Control port bound to localhost only (`127.0.0.1:9051`)

- **Repository safety**  
  Tor Project signing key fingerprint is verified before trust

- **Clean configuration management**  
  Existing `/etc/tor/torrc` is backed up before replacement

- **Operator friendly**  
  Interactive prompts with sensible defaults and automation support via environment variables

---

## System Requirements

### Server

- Ubuntu or Debian (Ubuntu 20.04 / 22.04 / 24.04 recommended)
- Root access (`sudo`)
- Public IPv4 address (recommended)

### Network / Hosting Provider

You must allow inbound TCP traffic on:

- **OR_PORT** — Tor ORPort (default: `9001`)
- **PT_PORT** — obfs4 transport port (default: `54321`)

If you are using a cloud provider (AWS, Hetzner, DigitalOcean, etc.), ensure these ports are opened in:
- the provider firewall / security group
- the OS firewall (UFW), if enabled

---

## Installation

### Interactive installation

Download and run the installer:

    wget https://raw.githubusercontent.com/<YOUR_USER>/<YOUR_REPO>/main/setup-bridge.sh
    chmod +x setup-bridge.sh
    sudo ./setup-bridge.sh

You will be prompted for:
- OR_PORT (Tor ORPort)
- PT_PORT (obfs4 transport port used by Tor Browser)
- optional contact email (ContactInfo)

After completion, the script prints your **obfs4 bridge line**.

---

### Non‑interactive / automated installation

You can predefine all values via environment variables:

    sudo OR_PORT=9001 PT_PORT=54321 EMAIL="ops@example.com" ./setup-bridge.sh

This is useful for automation, CI, or reproducible deployments.

---

## Client Configuration (Tor Browser)

After installation you will receive a bridge line similar to:

    obfs4 <SERVER_IP>:54321 <FINGERPRINT> cert=<LONG_STRING> iat-mode=0

To connect:

1. Open **Tor Browser**
2. Go to **Settings → Connection**
3. Enable **Bridges**
4. Select **Add bridge** → **Add new bridges**
5. Paste the full bridge line
6. Click **Next** → **Connect**

---

## Operations & Maintenance

### Status dashboard (Nyx)

    sudo nyx

Press `q` to exit.

### Logs

    sudo journalctl -u tor -e

### Restart Tor

    sudo systemctl restart tor

### Verify listening ports

Example using default ports:

    sudo ss -tulpn | egrep '(:9001|:54321)'

Replace with your custom ports if different.

### Retrieve bridge line again

    sudo cat /var/lib/tor/pt_state/obfs4_bridgeline.txt

---

## Tor Configuration Details

The installer writes `/etc/tor/torrc` with a bridge‑focused configuration, including:

- `BridgeRelay 1`
- `PublishServerDescriptor 0`
- `ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy`
- `ServerTransportListenAddr obfs4 0.0.0.0:<PT_PORT>`
- `ORPort <OR_PORT>`
- `SocksPort 0`
- `ControlPort 127.0.0.1:9051`
- `CookieAuthentication 1`

The configuration is validated automatically using:

    tor --verify-config -f /etc/tor/torrc

---

## Updating Tor

Tor and obfs4proxy are installed via APT. To update:

    sudo apt update && sudo apt upgrade -y

---

## Troubleshooting

### Bridge line not generated

Check Tor logs:

    sudo journalctl -u tor -e

Common causes:
- Provider firewall blocking ports
- UFW enabled without required rules
- Port conflict with another service
- Provider‑level traffic filtering

### Client cannot connect

Verify:
1. Provider firewall allows **OR_PORT** and **PT_PORT**
2. OS firewall (UFW) allows both ports
3. Tor service is running:

       systemctl status tor --no-pager

4. Ports are listening:

       sudo ss -tulpn | egrep '(:<OR_PORT>|:<PT_PORT>)'

---

## Security Notes

- Treat your bridge line as **sensitive information**. Share only with trusted users.
- Keep the operating system fully patched.
- Apply basic server hardening:
  - SSH key‑only authentication
  - Disable root SSH login
  - Use fail2ban
  - Expose only required ports

The installer intentionally **does not modify SSH firewall rules** to prevent accidental lockout.

---

## Repository Layout

    .
    ├── setup-bridge.sh
    └── README.md

---

## License

Add a `LICENSE` file (MIT is commonly used). Without a license, others may not have legal permission to reuse or modify this project.
