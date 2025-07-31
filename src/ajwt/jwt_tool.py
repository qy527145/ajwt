"""
Enhanced JWT analysis tool with detailed token inspection capabilities.
"""
import json
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import argparse

from .jwt_parser import JWTParser, JWTParseError


class JWTAnalyzer:
    """Enhanced JWT token analyzer with detailed inspection capabilities."""

    @staticmethod
    def format_json(data: Dict[str, Any], indent: int = 2) -> str:
        """Format dictionary as pretty JSON."""
        return json.dumps(data, indent=indent, ensure_ascii=False, sort_keys=True)

    @staticmethod
    def format_timestamp(timestamp: int) -> str:
        """Format Unix timestamp to human-readable string."""
        try:
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
        except (ValueError, OSError):
            return f"Invalid timestamp: {timestamp}"

    @staticmethod
    def analyze_claims(payload: Dict[str, Any]) -> Dict[str, str]:
        """Analyze standard JWT claims and provide human-readable descriptions."""
        analysis = {}

        # Standard claims
        standard_claims = {
            'iss': 'Issuer',
            'sub': 'Subject',
            'aud': 'Audience',
            'exp': 'Expiration Time',
            'nbf': 'Not Before',
            'iat': 'Issued At',
            'jti': 'JWT ID'
        }

        for claim, description in standard_claims.items():
            if claim in payload:
                value = payload[claim]
                if claim in ['exp', 'nbf', 'iat'] and isinstance(value, int):
                    analysis[claim] = f"{description}: {JWTAnalyzer.format_timestamp(value)} ({value})"
                else:
                    analysis[claim] = f"{description}: {value}"

        return analysis

    @staticmethod
    def check_token_validity(payload: Dict[str, Any]) -> Dict[str, str]:
        """Check token validity based on time claims."""
        now = datetime.now(timezone.utc).timestamp()
        validity = {}

        if 'exp' in payload:
            exp = payload['exp']
            if isinstance(exp, int):
                if exp < now:
                    validity['expiration'] = f"❌ EXPIRED (expired {JWTAnalyzer.format_timestamp(exp)})"
                else:
                    validity['expiration'] = f"✅ Valid until {JWTAnalyzer.format_timestamp(exp)}"

        if 'nbf' in payload:
            nbf = payload['nbf']
            if isinstance(nbf, int):
                if nbf > now:
                    validity['not_before'] = f"❌ NOT YET VALID (valid from {JWTAnalyzer.format_timestamp(nbf)})"
                else:
                    validity['not_before'] = f"✅ Valid since {JWTAnalyzer.format_timestamp(nbf)}"

        return validity

    def analyze_token(self, token: str) -> None:
        """
        Perform comprehensive analysis of a JWT token.

        Args:
            token: JWT token string
        """
        try:
            components = JWTParser.parse(token)

            print("=" * 80)
            print("JWT TOKEN ANALYSIS")
            print("=" * 80)

            # Header analysis
            print("\n📋 HEADER:")
            print("-" * 40)
            print(self.format_json(components.header))

            # Algorithm analysis
            alg = components.header.get('alg', 'none')
            print(f"\n🔐 Algorithm: {alg}")
            if alg == 'none':
                print("⚠️  WARNING: 'none' algorithm - token is not signed!")
            elif alg.startswith('HS'):
                print("🔑 HMAC-based signature (symmetric key)")
            elif alg.startswith('RS') or alg.startswith('PS'):
                print("🔑 RSA-based signature (asymmetric key)")
            elif alg.startswith('ES'):
                print("🔑 ECDSA-based signature (asymmetric key)")

            # Payload analysis
            print("\n📦 PAYLOAD:")
            print("-" * 40)
            print(self.format_json(components.payload))

            # Claims analysis
            claims_analysis = self.analyze_claims(components.payload)
            if claims_analysis:
                print("\n📝 STANDARD CLAIMS:")
                print("-" * 40)
                for claim_info in claims_analysis.values():
                    print(f"  {claim_info}")

            # Validity check
            validity = self.check_token_validity(components.payload)
            if validity:
                print("\n⏰ TOKEN VALIDITY:")
                print("-" * 40)
                for check in validity.values():
                    print(f"  {check}")

            # Signature analysis
            print(f"\n🔏 SIGNATURE:")
            print("-" * 40)
            print(f"  Length: {len(components.signature)} bytes ({len(components.signature) * 8} bits)")
            print(f"  Raw signature (hex): {components.signature.hex()}")

            # Token structure
            print(f"\n📏 TOKEN STRUCTURE:")
            print("-" * 40)
            print(f"  Header length: {len(components.raw_header)} chars")
            print(f"  Payload length: {len(components.raw_payload)} chars")
            print(f"  Signature length: {len(components.raw_signature)} chars")
            print(f"  Total token length: {len(token)} chars")

        except JWTParseError as e:
            print(f"❌ JWT Parse Error: {e}")
        except Exception as e:
            print(f"❌ Unexpected error: {e}")


def main():
    """Main function for JWT analysis tool."""
    parser = argparse.ArgumentParser(description="Enhanced JWT Token Analyzer")
    parser.add_argument('--token', '-t', help='JWT token to analyze')
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Run in interactive mode (default)')

    args = parser.parse_args()

    analyzer = JWTAnalyzer()

    if args.token:
        # Single token analysis
        analyzer.analyze_token(args.token)
    else:
        # Interactive mode
        print("Enhanced JWT Token Analyzer")
        print("Enter JWT tokens for analysis (Ctrl+C to exit)")
        print("=" * 50)

        while True:
            try:
                token = input("\nEnter JWT Token: ").strip()
                if not token:
                    print("Please enter a valid JWT token")
                    continue

                analyzer.analyze_token(token)

            except KeyboardInterrupt:
                print("\n\nExiting...")
                break
            except EOFError:
                print("\nExiting...")
                break


if __name__ == "__main__":
    main()
