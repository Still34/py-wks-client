# py-wks-client

A pure Python implementation of the OpenPGP Web Key Service (WKS) client protocol, aiming to be (somewhat) compatible with `gpg-wks-client` from GnuPG.

## Overview

This tool implements the Web Key Service client functionality for discovering OpenPGP keys via HTTPS. It supports some of the basic `gpg-wks-client` operations without requiring GnuPG installation and works cross-platform.

## Requirements

- Python 3
- Package(s) from [requirements.txt](./requirements.txt)

## Usage

### Syntax

```
wks_client.py [command] [options] [args]
```

### Commands

| Command                           | Description                               |
| --------------------------------- | ----------------------------------------- |
| `check EMAIL`                     | Check whether a key is available via WKD  |
| `supported DOMAIN`                | Check whether a domain supports WKS       |
| `create EMAIL`                    | Create a publication request email        |
| `print-wkd-hash EMAIL [EMAIL...]` | Print WKD identifiers for email addresses |
| `print-wkd-url EMAIL`             | Print WKD URLs for an email address       |

### Options

| Option                   | Description                                         |
| ------------------------ | --------------------------------------------------- |
| `-v, --verbose`          | Enable verbose output                               |
| `-q, --quiet`            | Suppress most output                                |
| `-o FILE, --output FILE` | Write output to FILE (for `create`/`check` command) |
| `-h, --help`             | Show help message                                   |

### Check if a key is published

```bash
$ python wks_client.py check user@example.org -v
gpg-wks-client: trying advanced method via URL 'https://openpgpkey.example.org/...'
gpg-wks-client: public key for 'user@example.org' found via WKD
gpg-wks-client: fingerprint: 2EFD19A196B620193A4647EEE914DA127CE5EDE7
gpg-wks-client:     user-id: John Doe <user@example.org>
gpg-wks-client:     created: Mon 17 Feb 2025 11:13:52 AM UTC
gpg-wks-client:   addr-spec: user@example.org
```

### Check domain WKS support

```bash
$ python wks_client.py supported debian.org
# Exit code 0 if supported, 1 if not

$ python wks_client.py supported example.com -v
gpg-wks-client: checking domain 'example.com'
gpg-wks-client: domain 'example.com' does NOT support WKS
```

### Print WKD hash for email

```bash
$ python wks_client.py print-wkd-hash user@example.org
iy9q119eutrkn8s1mk4r39qejnbu3n5q user@example.org

$ python wks_client.py print-wkd-hash user1@ex.org user2@ex.org
8seby6x8x4krk5k6ig17bpptwgd5ag9c user1@ex.org
hu1zi1dgu4406ehbqtx91onukwqr5u51 user2@ex.org
```

### Print WKD URLs

```bash
$ python wks_client.py print-wkd-url user@example.org
Advanced: https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q
Direct:   https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q
```

## Acknowledgments

Based on the OpenPGP [Web Key Service specification](https://web.archive.org/web/20250911090631/https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service) by Werner Koch and the GnuPG project.
