"""
JWT parsing utilities for JWT analysis tools.
"""
import base64
import json
from dataclasses import dataclass
from typing import Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class JWTParseError(Exception):
    """Custom exception for JWT parsing errors."""
    pass


@dataclass
class JWTComponents:
    """Represents the components of a JWT token."""
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    message: bytes
    raw_header: str
    raw_payload: str
    raw_signature: str


class JWTParser:
    """JWT token parser with validation and error handling."""
    
    @staticmethod
    def _add_padding(data: str) -> str:
        """Add padding to base64 string if needed."""
        return data + "=" * (-len(data) % 4)
    
    @staticmethod
    def _decode_base64url(data: str) -> bytes:
        """Decode base64url encoded string."""
        try:
            padded = JWTParser._add_padding(data)
            return base64.urlsafe_b64decode(padded)
        except Exception as e:
            raise JWTParseError(f"Failed to decode base64url data: {e}")
    
    @staticmethod
    def _decode_json(data: bytes) -> Dict[str, Any]:
        """Decode JSON from bytes."""
        try:
            return json.loads(data.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise JWTParseError(f"Failed to decode JSON: {e}")
    
    @classmethod
    def parse(cls, token: str) -> JWTComponents:
        """
        Parse a JWT token into its components.
        
        Args:
            token: The JWT token string
            
        Returns:
            JWTComponents object containing parsed data
            
        Raises:
            JWTParseError: If the token is invalid or cannot be parsed
        """
        if not token or not isinstance(token, str):
            raise JWTParseError("Token must be a non-empty string")
        
        # Split token into parts
        parts = token.split('.')
        if len(parts) != 3:
            raise JWTParseError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
        
        raw_header, raw_payload, raw_signature = parts
        
        # Decode header
        try:
            header_bytes = cls._decode_base64url(raw_header)
            header = cls._decode_json(header_bytes)
        except JWTParseError as e:
            raise JWTParseError(f"Failed to parse header: {e}")
        
        # Decode payload
        try:
            payload_bytes = cls._decode_base64url(raw_payload)
            payload = cls._decode_json(payload_bytes)
        except JWTParseError as e:
            raise JWTParseError(f"Failed to parse payload: {e}")
        
        # Decode signature
        try:
            signature = cls._decode_base64url(raw_signature)
        except JWTParseError as e:
            raise JWTParseError(f"Failed to parse signature: {e}")
        
        # Create message for verification
        message = f"{raw_header}.{raw_payload}".encode('utf-8')
        
        return JWTComponents(
            header=header,
            payload=payload,
            signature=signature,
            message=message,
            raw_header=raw_header,
            raw_payload=raw_payload,
            raw_signature=raw_signature
        )
    
    @staticmethod
    def get_algorithm(token: str) -> str:
        """
        Extract the algorithm from JWT header.
        
        Args:
            token: The JWT token string
            
        Returns:
            The algorithm string
            
        Raises:
            JWTParseError: If algorithm cannot be extracted
        """
        components = JWTParser.parse(token)
        alg = components.header.get('alg')
        if not alg:
            raise JWTParseError("No algorithm specified in JWT header")
        return alg
    
    @staticmethod
    def validate_algorithm(algorithm: str, supported_algorithms: set) -> None:
        """
        Validate that the algorithm is supported.
        
        Args:
            algorithm: The algorithm to validate
            supported_algorithms: Set of supported algorithms
            
        Raises:
            JWTParseError: If algorithm is not supported
        """
        if algorithm not in supported_algorithms:
            raise JWTParseError(
                f"Unsupported algorithm '{algorithm}'. "
                f"Supported: {', '.join(sorted(supported_algorithms))}"
            )
