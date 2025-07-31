"""
JWT analysis and attack tools.
"""

from .jwt_parser import JWTParser, JWTParseError, JWTComponents
from .jwt_tool import JWTAnalyzer
from .rsa_tool import RSAAttacker, RSAAttackError

__version__ = "1.0.0"
__all__ = [
    "JWTParser",
    "JWTParseError",
    "JWTComponents",
    "JWTAnalyzer",
    "RSAAttacker",
    "RSAAttackError",
]


def hello() -> str:
    return "Hello from jwt-tool!"
