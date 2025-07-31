"""
Simple test script for the optimized JWT tools.
"""
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from ajwt.jwt_parser import JWTParser, JWTParseError
from ajwt.jwt_tool import JWTAnalyzer

# Sample JWT token for testing (this is a test token, not a real one)
SAMPLE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def test_jwt_parser():
    """Test the JWT parser functionality."""
    print("Testing JWT Parser...")
    
    try:
        components = JWTParser.parse(SAMPLE_JWT)
        print(f"✅ Successfully parsed JWT")
        print(f"   Algorithm: {components.header.get('alg')}")
        print(f"   Subject: {components.payload.get('sub')}")
        print(f"   Name: {components.payload.get('name')}")
        print(f"   Signature length: {len(components.signature)} bytes")
        return True
    except JWTParseError as e:
        print(f"❌ JWT parsing failed: {e}")
        return False

def test_jwt_analyzer():
    """Test the JWT analyzer functionality."""
    print("\nTesting JWT Analyzer...")
    
    try:
        analyzer = JWTAnalyzer()
        print("✅ JWT Analyzer created successfully")
        
        # Test JSON formatting
        test_data = {"alg": "HS256", "typ": "JWT"}
        formatted = analyzer.format_json(test_data)
        print(f"✅ JSON formatting works: {len(formatted)} chars")
        
        return True
    except Exception as e:
        print(f"❌ JWT Analyzer test failed: {e}")
        return False

def test_invalid_jwt():
    """Test error handling with invalid JWT."""
    print("\nTesting error handling...")
    
    invalid_tokens = [
        "invalid.jwt",  # Only 2 parts
        "invalid.jwt.token.extra",  # Too many parts
        "",  # Empty string
        "not.a.jwt",  # Invalid base64
    ]
    
    for token in invalid_tokens:
        try:
            JWTParser.parse(token)
            print(f"❌ Should have failed for: {token}")
            return False
        except JWTParseError:
            print(f"✅ Correctly rejected invalid token: {token[:20]}...")
    
    return True

def main():
    """Run all tests."""
    print("JWT Tools Test Suite")
    print("=" * 50)
    
    tests = [
        test_jwt_parser,
        test_jwt_analyzer,
        test_invalid_jwt,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
