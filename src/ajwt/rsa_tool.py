"""
RSA JWT attack tool for recovering RSA public keys from multiple JWT tokens.
"""
import logging
import time
from functools import wraps
from multiprocessing import Pool
from typing import List, Tuple, Optional, Set
import sys

import gmpy2
from Crypto import Hash
from Crypto.Signature.pkcs1_15 import _EMSA_PKCS1_V1_5_ENCODE  # noqa
from Crypto.Signature.pss import _EMSA_PSS_ENCODE  # noqa
from crypto_plus import CryptoPlus

from .jwt_parser import JWTParser, JWTParseError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration constants
DEFAULT_MAX_PROCESSES = 8
DEFAULT_PRIME_LIMIT = 100
RSA_PUBLIC_EXPONENT = 65537

# Supported RSA algorithms mapping
SUPPORTED_RSA_ALGORITHMS = {
    "RS256": ("SHA256", _EMSA_PKCS1_V1_5_ENCODE),
    "RS384": ("SHA384", _EMSA_PKCS1_V1_5_ENCODE),
    "RS512": ("SHA512", _EMSA_PKCS1_V1_5_ENCODE),
    "PS256": ("SHA256", _EMSA_PSS_ENCODE),
    "PS384": ("SHA384", _EMSA_PSS_ENCODE),
    "PS512": ("SHA512", _EMSA_PSS_ENCODE),
}


class RSAAttackError(Exception):
    """Custom exception for RSA attack related errors."""
    pass


def timer(loop: int = 1):
    """
    Decorator for timing function execution.

    Args:
        loop: Number of times to execute the function (default: 1)
    """
    def outer(func):
        @wraps(func)
        def inner(*args, **kwargs):
            res = None
            start = time.perf_counter()
            logger.info(f"[{func.__name__}] Starting execution")

            # Call the actual function
            for _ in range(loop):
                res = func(*args, **kwargs)

            duration = time.perf_counter() - start
            logger.info(f"[{func.__name__}] Completed in {duration:.3f} seconds")
            return res

        return inner
    return outer


def calculate_rsa_modulus(token: str) -> gmpy2.mpz:
    """
    Calculate RSA modulus from a JWT token using the RSA signature vulnerability.

    Args:
        token: JWT token string

    Returns:
        Calculated RSA modulus as gmpy2.mpz

    Raises:
        RSAAttackError: If token parsing or calculation fails
    """
    try:
        # Parse JWT token
        components = JWTParser.parse(token)
        algorithm = components.header.get('alg')

        # Validate algorithm
        if algorithm not in SUPPORTED_RSA_ALGORITHMS:
            raise RSAAttackError(f"Unsupported algorithm: {algorithm}")

        hash_alg_name, encode_func = SUPPORTED_RSA_ALGORITHMS[algorithm]
        hash_alg = getattr(Hash, hash_alg_name)

        # Calculate modulus using the RSA signature vulnerability
        signature_int = gmpy2.mpz(int.from_bytes(components.signature))
        encoded_message = encode_func(hash_alg.new(components.message), len(components.signature))

        return signature_int ** gmpy2.mpz(RSA_PUBLIC_EXPONENT) - int.from_bytes(encoded_message)

    except (JWTParseError, AttributeError, ValueError) as e:
        raise RSAAttackError(f"Failed to calculate RSA modulus: {e}")


def generate_primes(limit: int = DEFAULT_PRIME_LIMIT):
    """
    Generate prime numbers up to the specified limit.

    Args:
        limit: Upper limit for prime generation

    Yields:
        Prime numbers
    """
    for i in range(2, limit):
        if gmpy2.is_prime(i):
            yield i


def remove_small_factors(number: gmpy2.mpz, prime_limit: int = DEFAULT_PRIME_LIMIT) -> gmpy2.mpz:
    """
    Remove small prime factors from a number.

    Args:
        number: Number to factor
        prime_limit: Upper limit for prime factors to remove

    Returns:
        Number with small factors removed
    """
    result = number
    for prime in generate_primes(prime_limit):
        while result % prime == 0:
            result = result // prime
    return result


@timer(1)
def batch_calculate_modulus(tokens: List[str], max_processes: int = DEFAULT_MAX_PROCESSES) -> gmpy2.mpz:
    """
    Calculate RSA modulus from multiple JWT tokens using parallel processing.

    Args:
        tokens: List of JWT token strings
        max_processes: Maximum number of processes to use

    Returns:
        Calculated RSA modulus

    Raises:
        RSAAttackError: If calculation fails
    """
    if not tokens:
        raise RSAAttackError("No tokens provided")

    try:
        with Pool(min(len(tokens), max_processes)) as pool:
            moduli = pool.map(calculate_rsa_modulus, tokens)

            if len(moduli) == 1:
                result = moduli[0]
            else:
                result = gmpy2.gcd(*moduli)

        # Remove small prime factors
        result = remove_small_factors(result)
        return result

    except Exception as e:
        raise RSAAttackError(f"Failed to calculate modulus: {e}")


@timer(1)
def verify_key_with_tokens(tokens: List[str], public_key: str) -> bool:
    """
    Verify that a public key can validate all provided JWT tokens.

    Args:
        tokens: List of JWT token strings
        public_key: PEM formatted public key

    Returns:
        True if all tokens are valid, False otherwise

    Raises:
        RSAAttackError: If verification process fails
    """
    try:
        rsa = CryptoPlus.loads(public_key)

        for token in tokens:
            components = JWTParser.parse(token)
            algorithm = components.header.get('alg')

            if algorithm not in SUPPORTED_RSA_ALGORITHMS:
                raise RSAAttackError(f"Unsupported algorithm: {algorithm}")

            hash_alg_name = SUPPORTED_RSA_ALGORITHMS[algorithm][0]

            if not rsa.verify(components.message, components.signature, hash_algorithm=hash_alg_name):
                return False

        return True

    except (JWTParseError, Exception) as e:
        raise RSAAttackError(f"Key verification failed: {e}")


def collect_tokens(min_tokens: int = 2) -> List[str]:
    """
    Collect JWT tokens from user input.

    Args:
        min_tokens: Minimum number of tokens required

    Returns:
        List of collected JWT tokens

    Raises:
        KeyboardInterrupt: If user cancels input
    """
    tokens = []
    print(f"Please enter at least {min_tokens} JWT tokens (press Enter with empty input when done):")

    while True:
        try:
            token = input(f"JWT Token #{len(tokens) + 1}: ").strip()
            if token:
                # Basic validation
                if len(token.split('.')) != 3:
                    print("Warning: Invalid JWT format (should have 3 parts separated by dots)")
                    continue
                tokens.append(token)
                print(f"Added token {len(tokens)}")
            elif len(tokens) >= min_tokens:
                return tokens
            else:
                print(f"Need at least {min_tokens} tokens, currently have {len(tokens)}")
        except KeyboardInterrupt:
            raise


def extract_modulus_from_key(public_key: str) -> int:
    """
    Extract the modulus (n) from a public key.

    Args:
        public_key: PEM formatted public key

    Returns:
        RSA modulus as integer
    """
    return CryptoPlus.loads(public_key).public_key.n


class RSAAttacker:
    """RSA JWT attack orchestrator."""

    def __init__(self, max_processes: int = DEFAULT_MAX_PROCESSES, prime_limit: int = DEFAULT_PRIME_LIMIT):
        self.max_processes = max_processes
        self.prime_limit = prime_limit
        self.accumulated_modulus: Optional[gmpy2.mpz] = None

    def attack(self, tokens: List[str]) -> Tuple[gmpy2.mpz, str]:
        """
        Perform RSA attack on JWT tokens.

        Args:
            tokens: List of JWT tokens

        Returns:
            Tuple of (modulus, public_key_pem)

        Raises:
            RSAAttackError: If attack fails
        """
        logger.info(f"Starting RSA attack with {len(tokens)} tokens")

        # Calculate modulus from tokens
        modulus = batch_calculate_modulus(tokens, self.max_processes)

        # Combine with previously accumulated modulus if available
        if self.accumulated_modulus:
            modulus = gmpy2.gcd(self.accumulated_modulus, modulus)
            logger.info("Combined with previous modulus")

        self.accumulated_modulus = modulus

        # Construct public key
        try:
            public_key = CryptoPlus.construct_rsa(n=int(modulus)).dumps()[1].decode()
        except Exception as e:
            raise RSAAttackError(f"Failed to construct public key: {e}")

        # Verify the key works with all tokens
        if not verify_key_with_tokens(tokens, public_key):
            raise RSAAttackError("Generated key failed verification")

        logger.info("RSA attack successful!")
        return modulus, public_key


def main():
    """Main function for RSA JWT attack tool."""
    print("RSA JWT Attack Tool")
    print("=" * 50)

    attacker = RSAAttacker()

    try:
        # Collect initial tokens
        tokens = collect_tokens(2)

        while True:
            try:
                # Perform attack
                modulus, public_key = attacker.attack(tokens)

                # Display results
                print("\n" + "=" * 50)
                print("ATTACK SUCCESSFUL!")
                print("=" * 50)
                print(f"RSA Modulus (n):")
                print(modulus)
                print(f"\nPublic Key (PEM):")
                print(public_key)
                print("=" * 50)
                break

            except RSAAttackError as e:
                logger.error(f"Attack failed: {e}")
                print(f"\nAttack failed: {e}")
                print("Try adding more tokens...")

                try:
                    additional_tokens = collect_tokens(1)
                    tokens.extend(additional_tokens)
                except KeyboardInterrupt:
                    print("\nExiting...")
                    break

            except KeyboardInterrupt:
                print("\nExiting...")
                break

    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
