#!/usr/bin/env python3

import hashlib
import sys
import argparse
from typing import Optional, Tuple, Dict
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
import urllib.request
import urllib.error
import datetime
import struct
import zbase32


class OpenPGPKeyParser:
    """Lightweight OpenPGP key parser (RFC 4880)"""

    @staticmethod
    def parse_packet_header(data: bytes, offset: int) -> Tuple[int, int, int]:
        """Parse OpenPGP packet header, returns (tag, length, header_len)"""
        if offset >= len(data):
            raise ValueError("Offset out of bounds")

        byte = data[offset]

        if byte & 0x80 == 0:
            raise ValueError("Invalid packet tag")

        if byte & 0x40:  # New format
            tag = byte & 0x3F
            if offset + 1 >= len(data):
                raise ValueError("Incomplete packet header")

            length_byte = data[offset + 1]

            if length_byte < 192:
                return tag, length_byte, 2
            elif length_byte < 224:
                if offset + 2 >= len(data):
                    raise ValueError("Incomplete packet header")
                return tag, ((length_byte - 192) << 8) + data[offset + 2] + 192, 3
            elif length_byte == 255:
                if offset + 5 >= len(data):
                    raise ValueError("Incomplete packet header")
                length = struct.unpack('>I', data[offset+2:offset+6])[0]
                return tag, length, 6
            else:
                raise ValueError("Partial body length not supported")
        else:  # Old format
            tag = (byte & 0x3C) >> 2
            length_type = byte & 0x03

            if length_type == 0:
                if offset + 1 >= len(data):
                    raise ValueError("Incomplete packet header")
                return tag, data[offset + 1], 2
            elif length_type == 1:
                if offset + 2 >= len(data):
                    raise ValueError("Incomplete packet header")
                return tag, struct.unpack('>H', data[offset+1:offset+3])[0], 3
            elif length_type == 2:
                if offset + 4 >= len(data):
                    raise ValueError("Incomplete packet header")
                return tag, struct.unpack('>I', data[offset+1:offset+5])[0], 5
            else:
                return tag, len(data) - offset - 1, 1

    @staticmethod
    def compute_v4_fingerprint(key_data: bytes, offset: int, length: int) -> str:
        """Compute V4 key fingerprint (SHA-1 of key material)"""
        material = key_data[offset:offset+length]
        to_hash = b'\x99' + struct.pack('>H', length) + material
        fp = hashlib.sha1(to_hash).hexdigest().upper()
        return fp

    @staticmethod
    def parse_public_key_packet(data: bytes) -> Dict:
        """Parse public key packet"""
        if len(data) < 6:
            return {}

        offset = 0
        version = data[offset]
        offset += 1

        if version not in (3, 4):
            return {}

        # Creation time (4 bytes)
        timestamp = struct.unpack('>I', data[offset:offset+4])[0]
        creation_time = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
        offset += 4

        if version == 3:
            offset += 2  # V3 validity period

        algorithm = data[offset] if offset < len(data) else 0

        return {
            'version': version,
            'created': creation_time,
            'algorithm': algorithm
        }

    @staticmethod
    def parse_user_id_packet(data: bytes) -> str:
        """Parse User ID packet"""
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.decode('latin-1', errors='ignore')

    @staticmethod
    def parse_key(key_data: bytes) -> Dict:
        """Parse OpenPGP public key"""
        result = {
            'fingerprint': None,
            'user_ids': [],
            'created': None
        }

        offset = 0

        while offset < len(key_data):
            try:
                tag, length, header_len = OpenPGPKeyParser.parse_packet_header(key_data, offset)
                packet_start = offset + header_len

                if packet_start + length > len(key_data):
                    break

                # Public Key Packet (tag 6)
                if tag == 6:
                    key_info = OpenPGPKeyParser.parse_public_key_packet(
                        key_data[packet_start:packet_start+length]
                    )
                    result['created'] = key_info.get('created')

                    if key_info.get('version') == 4:
                        result['fingerprint'] = OpenPGPKeyParser.compute_v4_fingerprint(
                            key_data, packet_start, length
                        )

                # User ID Packet (tag 13)
                elif tag == 13:
                    user_id = OpenPGPKeyParser.parse_user_id_packet(
                        key_data[packet_start:packet_start+length]
                    )
                    result['user_ids'].append(user_id)

                offset = packet_start + length

            except Exception:
                break

        return result


class WKSClient:
    """Web Key Service Client"""

    ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"

    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self.timeout = 10
        self.prefix = "gpg-wks-client"

    def log(self, message: str):
        """Print with gpg-wks-client prefix"""
        if not self.quiet:
            print(f"{self.prefix}: {message}")

    def zbase32_encode(self, data: bytes) -> str:
        """Encode to z-base32"""
        return zbase32.encode(data)

    def compute_wkd_hash(self, local_part: str) -> str:
        """Compute WKD hash"""
        local_lower = local_part.lower()
        sha1_hash = hashlib.sha1(local_lower.encode('utf-8')).digest()
        return self.zbase32_encode(sha1_hash)

    def parse_email(self, email: str) -> Tuple[str, str]:
        """Parse email address"""
        if '@' not in email:
            raise ValueError(f"Invalid email: {email}")
        local, domain = email.rsplit('@', 1)
        return local.lower(), domain.lower()

    def build_wkd_url(self, email: str, advanced: bool = True) -> str:
        """Build WKD URL"""
        local, domain = self.parse_email(email)
        wkd_hash = self.compute_wkd_hash(local)

        if advanced:
            return f"https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/hu/{wkd_hash}?l={local}"
        else:
            return f"https://{domain}/.well-known/openpgpkey/hu/{wkd_hash}"

    def check_support(self, domain: str, advanced: bool = True) -> bool:
        """Check if domain supports WKS"""
        if advanced:
            url = f"https://openpgpkey.{domain}/.well-known/openpgpkey/{domain}/policy"
        else:
            url = f"https://{domain}/.well-known/openpgpkey/policy"

        try:
            req = urllib.request.Request(url, method='GET')
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status == 200
        except urllib.error.HTTPError as e:
            return e.code == 404
        except:
            return False

    def fetch_key(self, email: str) -> Optional[bytes]:
        """Fetch key from WKD"""
        for advanced in [True, False]:
            url = self.build_wkd_url(email, advanced=advanced)

            if self.verbose:
                method = "advanced" if advanced else "direct"
                self.log(f"trying {method} method via URL '{url}'")

            try:
                req = urllib.request.Request(url, method='GET')
                req.add_header('User-Agent', 'Python-WKS-Client/1.0')
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        return resp.read()
            except Exception as e:
                if self.verbose:
                    self.log(f"error: {e}")
                continue

        return None

    def cmd_check(self, email: str, output: Optional[str] = None) -> int:
        """Check if email has published key"""
        try:
            print(email)
            print(output)
            key_data = self.fetch_key(email)

            if not key_data:
                self.log(f"public key for '{email}' NOT found via WKD")
                return 1

            parser = OpenPGPKeyParser()
            key_info = parser.parse_key(key_data)

            self.log(f"public key for '{email}' found via WKD")

            if key_info['fingerprint']:
                self.log(f"fingerprint: {key_info['fingerprint']}")

            for user_id in key_info['user_ids']:
                self.log(f"    user-id: {user_id}")

            if key_info['created']:
                created_str = key_info['created'].strftime('%a %d %b %Y %I:%M:%S %p UTC')
                self.log(f"    created: {created_str}")

            self.log(f"  addr-spec: {email}")

            # Save key to file if -o specified
            if output:
                with open(output, 'wb') as f:
                    f.write(key_data)
                if self.verbose:
                    self.log(f"key saved to '{output}' ({len(key_data)} bytes)")

            return 0

        except Exception as e:
            self.log(f"error: {e}")
            return 1

    def cmd_supported(self, domain: str) -> int:
        """Check if domain supports WKS"""
        if self.verbose:
            self.log(f"checking domain '{domain}'")

        if self.check_support(domain, True):
            if self.verbose:
                self.log(f"domain '{domain}' supports WKS (advanced method)")
            return 0

        if self.check_support(domain, False):
            if self.verbose:
                self.log(f"domain '{domain}' supports WKS (direct method)")
            return 0

        if not self.quiet:
            self.log(f"domain '{domain}' does NOT support WKS")
        return 1

    def cmd_create(self, email: str, key_data: str = None, output: str = None) -> int:
        """Create submission request"""
        try:
            local, domain = self.parse_email(email)

            msg = MIMEMultipart()
            msg['From'] = email
            msg['To'] = f"key-submission@{domain}"
            msg['Subject'] = 'Key publishing request'

            body = MIMEText("Request to publish key via Web Key Service.\n")
            msg.attach(body)

            if key_data:
                key_bytes = key_data.encode('utf-8') if isinstance(key_data, str) else key_data
                key_part = MIMEApplication(key_bytes, _subtype='pgp-keys')
                key_part.add_header('Content-Disposition', 'attachment', filename='key.asc')
                msg.attach(key_part)

            result = msg.as_string()

            if output:
                with open(output, 'w') as f:
                    f.write(result)
                if self.verbose:
                    self.log(f"submission request written to '{output}'")
            else:
                print(result)

            return 0

        except Exception as e:
            self.log(f"error: {e}")
            return 1

    def cmd_print_wkd_hash(self, *emails: str) -> int:
        """Print WKD hash for email addresses"""
        try:
            for email in emails:
                local, domain = self.parse_email(email)
                wkd_hash = self.compute_wkd_hash(local)
                print(f"{wkd_hash} {email}")
            return 0
        except Exception as e:
            self.log(f"error: {e}")
            return 1

    def cmd_print_wkd_url(self, email: str) -> int:
        """Print WKD URL for email address"""
        try:
            # Print both advanced and direct URLs
            advanced_url = self.build_wkd_url(email, advanced=True)
            direct_url = self.build_wkd_url(email, advanced=False)

            print(f"Advanced: {advanced_url}")
            print(f"Direct:   {direct_url}")
            return 0
        except Exception as e:
            self.log(f"error: {e}")
            return 1


def main():
    """CLI entry point using argparse with subparsers"""

    # Main parser
    parser = argparse.ArgumentParser(
        prog='wks_client.py',
        description='Client for the Web Key Service',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  wks_client.py check user@example.org -v
  wks_client.py supported example.org
  wks_client.py print-wkd-hash user1@example.org user2@example.org
"""
    )

    # Global options
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')
    parser.add_argument('-q', '--quiet', action='store_true', help='be somewhat more quiet')

    # Subparsers for commands
    subparsers = parser.add_subparsers(dest='command', metavar='command', help='command to execute')

    # check command
    parser_check = subparsers.add_parser('check', help='check whether a key is available')
    parser_check.add_argument('email', metavar='EMAIL', help='email address to check')
    parser_check.add_argument('-o', '--output', metavar='FILE', help='save the public key to FILE')

    # supported command
    parser_supported = subparsers.add_parser('supported', help='check whether provider supports WKS')
    parser_supported.add_argument('domain', metavar='DOMAIN', help='domain to check')

    # create command
    parser_create = subparsers.add_parser('create', help='create a publication request')
    parser_create.add_argument('email', metavar='EMAIL', help='email address for key submission')
    parser_create.add_argument('-o', '--output', metavar='FILE', help='write the mail to FILE')

    # print-wkd-hash command
    parser_hash = subparsers.add_parser('print-wkd-hash', help='print WKD identifier for user ids')
    parser_hash.add_argument('emails', metavar='EMAIL', nargs='+', help='email address(es) to hash')

    # print-wkd-url command
    parser_url = subparsers.add_parser('print-wkd-url', help='print WKD URL for user id')
    parser_url.add_argument('email', metavar='EMAIL', help='email address')

    # Parse arguments
    args = parser.parse_args()

    # If no command provided, show help
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Create client with options
    client = WKSClient(verbose=args.verbose, quiet=args.quiet)

    # Execute command
    if args.command == 'check':
        sys.exit(client.cmd_check(args.email, output=args.output))

    elif args.command == 'supported':
        sys.exit(client.cmd_supported(args.domain))

    elif args.command == 'create':
        sys.exit(client.cmd_create(args.email, output=args.output))

    elif args.command == 'print-wkd-hash':
        sys.exit(client.cmd_print_wkd_hash(*args.emails))

    elif args.command == 'print-wkd-url':
        sys.exit(client.cmd_print_wkd_url(args.email))

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
