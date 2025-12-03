"""
FastAPI web application for JWT generation and validation.
"""
import base64
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, SHA384, SHA512
from Crypto.Signature import pkcs1_15, pss
from crypto_plus import CryptoPlus

from .jwt_parser import JWTParser, JWTParseError

app = FastAPI(title="AJWT Web Tool", description="JWT Generation and Validation Tool")

# Supported algorithms
SUPPORTED_ALGORITHMS = {
    "RS256": (SHA256, pkcs1_15),
    "RS384": (SHA384, pkcs1_15),
    "RS512": (SHA512, pkcs1_15),
    "PS256": (SHA256, pss),
    "PS384": (SHA384, pss),
    "PS512": (SHA512, pss),
}


class KeyPairResponse(BaseModel):
    """Response model for key pair generation."""
    private_key: str
    public_key: str
    key_size: int


class JWTGenerateRequest(BaseModel):
    """Request model for JWT generation."""
    header: Dict[str, Any] = Field(default={"alg": "RS256", "typ": "JWT"})
    payload: Dict[str, Any] = Field(default={})
    private_key: str = Field(..., description="PEM formatted private key")
    algorithm: str = Field(default="RS256", description="Signing algorithm")


class JWTValidateRequest(BaseModel):
    """Request model for JWT validation."""
    token: str = Field(..., description="JWT token to validate")
    public_key: Optional[str] = Field(None, description="PEM formatted public key for signature verification")


class JWTValidateResponse(BaseModel):
    """Response model for JWT validation."""
    valid: bool
    header: Optional[Dict[str, Any]] = None
    payload: Optional[Dict[str, Any]] = None
    signature_valid: Optional[bool] = None
    error: Optional[str] = None
    decoded_info: Optional[Dict[str, Any]] = None


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes."""
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main HTML page."""
    return """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AJWT - JWT工具</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
        }

        h1 {
            color: white;
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            margin-bottom: 20px;
        }

        .card h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.5em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 600;
        }

        input[type="text"],
        input[type="number"],
        textarea,
        select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: all 0.3s;
        }

        input:focus,
        textarea:focus,
        select:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        textarea {
            font-family: 'Courier New', monospace;
            resize: vertical;
            min-height: 100px;
        }

        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
            width: 100%;
            margin-top: 10px;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn-secondary {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }

        .btn-success {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }

        .result {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
            word-break: break-all;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            max-height: 300px;
            overflow-y: auto;
        }

        .success {
            background: #d4edda;
            border-left: 4px solid #28a745;
            color: #155724;
        }

        .error {
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            color: #721c24;
        }

        .info {
            background: #d1ecf1;
            border-left: 4px solid #17a2b8;
            color: #0c5460;
        }

        .json-editor {
            min-height: 150px;
        }

        .key-display {
            background: #2d3748;
            color: #68d391;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            max-height: 200px;
            overflow-y: auto;
            margin-top: 10px;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .tab {
            padding: 10px 20px;
            background: #e0e0e0;
            border: none;
            border-radius: 8px 8px 0 0;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }

        .tab.active {
            background: white;
            color: #667eea;
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        .file-upload {
            border: 2px dashed #667eea;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
        }

        .file-upload:hover {
            background: rgba(102, 126, 234, 0.05);
        }

        .file-upload input[type="file"] {
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 AJWT - JWT 生成与验证工具</h1>
        
        <!-- Key Management Card -->
        <div class="card">
            <h2>🔑 密钥管理</h2>
            
            <div class="tabs">
                <button class="tab active" onclick="switchTab('generate')">生成密钥对</button>
                <button class="tab" onclick="switchTab('upload')">上传私钥</button>
            </div>

            <!-- Generate Key Tab -->
            <div id="generate-tab" class="tab-content active">
                <div class="form-group">
                    <label for="keySize">密钥长度 (bits)</label>
                    <select id="keySize">
                        <option value="1024">1024</option>
                        <option value="2048" selected>2048</option>
                        <option value="3072">3072</option>
                        <option value="4096">4096</option>
                    </select>
                </div>
                <button class="btn" onclick="generateKeyPair()">生成RSA密钥对</button>
            </div>

            <!-- Upload Key Tab -->
            <div id="upload-tab" class="tab-content">
                <div class="form-group">
                    <label for="privateKeyInput">私钥 (PEM格式)</label>
                    <textarea id="privateKeyInput" rows="8" placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"></textarea>
                </div>
                <button class="btn btn-secondary" onclick="loadPrivateKey()">加载私钥</button>
            </div>

            <div id="keyResult" class="result" style="display:none;"></div>
        </div>

        <!-- JWT Generation Card -->
        <div class="card">
            <h2>✨ JWT 生成</h2>
            
            <div class="form-group">
                <label for="algorithm">签名算法</label>
                <select id="algorithm">
                    <option value="RS256">RS256 (SHA-256)</option>
                    <option value="RS384">RS384 (SHA-384)</option>
                    <option value="RS512">RS512 (SHA-512)</option>
                    <option value="PS256">PS256 (SHA-256 PSS)</option>
                    <option value="PS384">PS384 (SHA-384 PSS)</option>
                    <option value="PS512">PS512 (SHA-512 PSS)</option>
                </select>
            </div>

            <div class="form-group">
                <label for="headerJson">Header (JSON)</label>
                <textarea id="headerJson" class="json-editor">{"alg": "RS256", "typ": "JWT"}</textarea>
            </div>

            <div class="form-group">
                <label for="payloadJson">Payload (JSON)</label>
                <textarea id="payloadJson" class="json-editor">{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}</textarea>
            </div>

            <button class="btn btn-success" onclick="generateJWT()">生成 JWT</button>
            
            <div id="jwtResult" class="result" style="display:none;"></div>
        </div>

        <!-- JWT Validation Card -->
        <div class="card">
            <h2>🔍 JWT 验证与解析</h2>
            
            <div class="form-group">
                <label for="jwtToken">JWT Token</label>
                <textarea id="jwtToken" rows="4" placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."></textarea>
            </div>

            <div class="form-group">
                <label for="publicKeyInput">
                    公钥 (PEM格式，可选)
                    <span style="font-size: 12px; color: #666; font-weight: normal;">
                        - 加载私钥后会自动填充
                    </span>
                </label>
                <textarea id="publicKeyInput" rows="6" placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----&#10;&#10;留空则仅解析，不验证签名"></textarea>
            </div>

            <button class="btn" onclick="validateJWT()">验证 JWT</button>
            
            <div id="validateResult" class="result" style="display:none;"></div>
        </div>
    </div>

    <script>
        let currentPrivateKey = '';
        let currentPublicKey = '';

        function switchTab(tab) {
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            
            // Update tab content
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(tab + '-tab').classList.add('active');
        }

        async function generateKeyPair() {
            const keySize = parseInt(document.getElementById('keySize').value);
            const resultDiv = document.getElementById('keyResult');
            
            try {
                resultDiv.style.display = 'block';
                resultDiv.className = 'result info';
                resultDiv.textContent = '正在生成密钥对...';

                const response = await fetch('/api/generate-keypair', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key_size: keySize})
                });

                const data = await response.json();
                
                if (response.ok) {
                    currentPrivateKey = data.private_key;
                    currentPublicKey = data.public_key;
                    
                    // Auto-fill public key to validation section
                    document.getElementById('publicKeyInput').value = data.public_key;
                    
                    resultDiv.className = 'result success';
                    resultDiv.innerHTML = `
                        <strong>✅ 密钥对生成成功!</strong><br>
                        <strong>密钥长度:</strong> ${data.key_size} bits<br><br>
                        <strong>私钥:</strong>
                        <div class="key-display">${escapeHtml(data.private_key)}</div>
                        <strong>公钥:</strong>
                        <div class="key-display">${escapeHtml(data.public_key)}</div>
                        <div style="margin-top: 10px; padding: 10px; background: #e7f3ff; border-radius: 4px; color: #004085;">
                            ℹ️ 公钥已自动填充到验证区域
                        </div>
                    `;
                    
                    // Update algorithm header
                    updateHeader();
                } else {
                    throw new Error(data.detail || '生成失败');
                }
            } catch (error) {
                resultDiv.className = 'result error';
                resultDiv.textContent = '❌ 错误: ' + error.message;
            }
        }

        async function loadPrivateKey() {
            const privateKey = document.getElementById('privateKeyInput').value.trim();
            const resultDiv = document.getElementById('keyResult');
            
            if (!privateKey) {
                resultDiv.style.display = 'block';
                resultDiv.className = 'result error';
                resultDiv.textContent = '❌ 请输入私钥';
                return;
            }
            
            currentPrivateKey = privateKey;
            
            // Extract public key from private key
            resultDiv.style.display = 'block';
            resultDiv.className = 'result info';
            resultDiv.textContent = '正在提取公钥...';
            
            try {
                const response = await fetch('/api/extract-public-key', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({private_key: privateKey})
                });

                const data = await response.json();
                
                if (response.ok) {
                    currentPublicKey = data.public_key;
                    
                    // Auto-fill public key to validation section
                    document.getElementById('publicKeyInput').value = data.public_key;
                    
                    resultDiv.className = 'result success';
                    resultDiv.innerHTML = `
                        <strong>✅ 私钥已加载!</strong><br>
                        <div class="key-display">${escapeHtml(privateKey)}</div>
                        <strong>提取的公钥:</strong>
                        <div class="key-display">${escapeHtml(data.public_key)}</div>
                        <div style="margin-top: 10px; padding: 10px; background: #e7f3ff; border-radius: 4px; color: #004085;">
                            ℹ️ 公钥已自动填充到验证区域
                        </div>
                    `;
                } else {
                    throw new Error(data.detail || '提取公钥失败');
                }
            } catch (error) {
                // If extraction fails, still load the private key
                currentPublicKey = '';
                resultDiv.className = 'result success';
                resultDiv.innerHTML = `
                    <strong>✅ 私钥已加载!</strong><br>
                    <div class="key-display">${escapeHtml(privateKey)}</div>
                    <div style="margin-top: 10px; padding: 10px; background: #fff3cd; border-radius: 4px; color: #856404;">
                        ⚠️ 无法自动提取公钥: ${error.message}
                    </div>
                `;
            }
            
            updateHeader();
        }

        function updateHeader() {
            const algorithm = document.getElementById('algorithm').value;
            try {
                const header = JSON.parse(document.getElementById('headerJson').value);
                header.alg = algorithm;
                document.getElementById('headerJson').value = JSON.stringify(header, null, 2);
            } catch (e) {
                // Ignore JSON parse errors
            }
        }

        async function generateJWT() {
            const resultDiv = document.getElementById('jwtResult');
            
            if (!currentPrivateKey) {
                resultDiv.style.display = 'block';
                resultDiv.className = 'result error';
                resultDiv.textContent = '❌ 请先生成或上传私钥';
                return;
            }

            try {
                const header = JSON.parse(document.getElementById('headerJson').value);
                const payload = JSON.parse(document.getElementById('payloadJson').value);
                const algorithm = document.getElementById('algorithm').value;

                resultDiv.style.display = 'block';
                resultDiv.className = 'result info';
                resultDiv.textContent = '正在生成 JWT...';

                const response = await fetch('/api/generate-jwt', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        header: header,
                        payload: payload,
                        private_key: currentPrivateKey,
                        algorithm: algorithm
                    })
                });

                const data = await response.json();
                
                if (response.ok) {
                    resultDiv.className = 'result success';
                    resultDiv.innerHTML = `
                        <strong>✅ JWT 生成成功!</strong><br><br>
                        <strong>Token:</strong><br>
                        <div style="word-break: break-all; margin-top: 10px; padding: 10px; background: white; border-radius: 4px;">
                            ${escapeHtml(data.token)}
                        </div>
                        <button class="btn" style="margin-top: 10px;" onclick="copyToClipboard('${data.token}')">📋 复制到剪贴板</button>
                    `;
                } else {
                    throw new Error(data.detail || '生成失败');
                }
            } catch (error) {
                resultDiv.className = 'result error';
                resultDiv.textContent = '❌ 错误: ' + error.message;
            }
        }

        async function validateJWT() {
            const token = document.getElementById('jwtToken').value.trim();
            const publicKey = document.getElementById('publicKeyInput').value.trim();
            const resultDiv = document.getElementById('validateResult');
            
            if (!token) {
                resultDiv.style.display = 'block';
                resultDiv.className = 'result error';
                resultDiv.textContent = '❌ 请输入 JWT Token';
                return;
            }

            try {
                resultDiv.style.display = 'block';
                resultDiv.className = 'result info';
                resultDiv.textContent = '正在验证 JWT...';

                const response = await fetch('/api/validate-jwt', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        token: token,
                        public_key: publicKey || null
                    })
                });

                const data = await response.json();
                
                if (response.ok) {
                    let html = '';
                    
                    if (data.valid) {
                        html += '<strong>✅ JWT 格式有效!</strong><br><br>';
                    } else {
                        html += '<strong>⚠️ JWT 解析结果:</strong><br><br>';
                    }
                    
                    if (data.header) {
                        html += '<strong>Header:</strong><br>';
                        html += `<pre>${JSON.stringify(data.header, null, 2)}</pre><br>`;
                    }
                    
                    if (data.payload) {
                        html += '<strong>Payload:</strong><br>';
                        html += `<pre>${JSON.stringify(data.payload, null, 2)}</pre><br>`;
                    }
                    
                    if (data.signature_valid !== null) {
                        if (data.signature_valid) {
                            html += '<strong>🔐 签名验证: ✅ 有效</strong><br>';
                        } else {
                            html += '<strong>🔐 签名验证: ❌ 无效</strong><br>';
                        }
                    }
                    
                    if (data.decoded_info) {
                        html += '<br><strong>解码信息:</strong><br>';
                        
                        // Display key info separately if present
                        if (data.decoded_info.key_info) {
                            html += '<div style="margin: 10px 0; padding: 10px; background: #e7f3ff; border-radius: 4px;">';
                            html += '<strong>🔑 密钥信息:</strong><br>';
                            html += `  模数长度: ${data.decoded_info.key_info.modulus_bits} bits (${data.decoded_info.key_info.modulus_bytes} bytes)`;
                            html += '</div>';
                        }
                        
                        html += `<pre>${JSON.stringify(data.decoded_info, null, 2)}</pre>`;
                    }
                    
                    if (data.error) {
                        html += `<br><strong>⚠️ 注意:</strong> ${escapeHtml(data.error)}`;
                    }
                    
                    resultDiv.className = data.valid ? 'result success' : 'result error';
                    resultDiv.innerHTML = html;
                } else {
                    throw new Error(data.detail || '验证失败');
                }
            } catch (error) {
                resultDiv.className = 'result error';
                resultDiv.textContent = '❌ 错误: ' + error.message;
            }
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('✅ 已复制到剪贴板!');
            }).catch(err => {
                alert('❌ 复制失败: ' + err);
            });
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Update header when algorithm changes
        document.getElementById('algorithm').addEventListener('change', updateHeader);
    </script>
</body>
</html>
    """


@app.post("/api/generate-keypair", response_model=KeyPairResponse)
async def generate_keypair(key_size: int = 2048):
    """Generate RSA key pair."""
    try:
        if key_size not in [1024, 2048, 3072, 4096]:
            raise HTTPException(status_code=400, detail="Invalid key size. Must be 1024, 2048, 3072, or 4096")
        
        # Generate RSA key pair
        key = RSA.generate(key_size)
        
        # Export keys in PEM format
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        
        return KeyPairResponse(
            private_key=private_key,
            public_key=public_key,
            key_size=key_size
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate key pair: {str(e)}")


class ExtractPublicKeyRequest(BaseModel):
    """Request model for extracting public key from private key."""
    private_key: str = Field(..., description="PEM formatted private key")


@app.post("/api/extract-public-key")
async def extract_public_key(request: ExtractPublicKeyRequest):
    """Extract public key from private key."""
    try:
        # Load private key using CryptoPlus
        try:
            rsa_key = CryptoPlus.loads(request.private_key)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid private key: {str(e)}")
        
        # Extract public key
        try:
            # Get the public key from the loaded private key
            public_key_obj = rsa_key.private_key.publickey()
            public_key = public_key_obj.export_key().decode('utf-8')
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to extract public key: {str(e)}")
        
        return {"public_key": public_key}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to extract public key: {str(e)}")


@app.post("/api/generate-jwt")
async def generate_jwt(request: JWTGenerateRequest):
    """Generate JWT token."""
    try:
        # Validate algorithm
        if request.algorithm not in SUPPORTED_ALGORITHMS:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported algorithm. Supported: {', '.join(SUPPORTED_ALGORITHMS.keys())}"
            )
        
        # Update header with algorithm
        header = request.header.copy()
        header['alg'] = request.algorithm
        
        # Encode header and payload
        header_encoded = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_encoded = base64url_encode(json.dumps(request.payload, separators=(',', ':')).encode('utf-8'))
        
        # Create message to sign
        message = f"{header_encoded}.{payload_encoded}".encode('utf-8')
        
        # Load private key
        try:
            rsa_key = CryptoPlus.loads(request.private_key)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid private key: {str(e)}")
        
        # Get hash algorithm and signature scheme
        hash_class, sig_scheme = SUPPORTED_ALGORITHMS[request.algorithm]
        
        # Sign the message
        try:
            hash_obj = hash_class.new(message)
            if sig_scheme == pkcs1_15:
                signature = pkcs1_15.new(rsa_key.private_key).sign(hash_obj)
            else:  # pss
                signature = pss.new(rsa_key.private_key).sign(hash_obj)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Signing failed: {str(e)}")
        
        # Encode signature
        signature_encoded = base64url_encode(signature)
        
        # Construct JWT
        token = f"{header_encoded}.{payload_encoded}.{signature_encoded}"
        
        return {"token": token}
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate JWT: {str(e)}")


@app.post("/api/validate-jwt", response_model=JWTValidateResponse)
async def validate_jwt(request: JWTValidateRequest):
    """Validate and parse JWT token."""
    try:
        # Parse JWT
        try:
            components = JWTParser.parse(request.token)
        except JWTParseError as e:
            return JWTValidateResponse(
                valid=False,
                error=f"JWT parsing failed: {str(e)}"
            )
        
        # Prepare response
        response = JWTValidateResponse(
            valid=True,
            header=components.header,
            payload=components.payload
        )
        
        # Add decoded information
        decoded_info = {}
        
        # Check time-based claims
        if 'exp' in components.payload:
            exp = components.payload['exp']
            if isinstance(exp, int):
                exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
                decoded_info['expiration'] = {
                    'timestamp': exp,
                    'datetime': exp_time.isoformat(),
                    'expired': exp < datetime.now(timezone.utc).timestamp()
                }
        
        if 'iat' in components.payload:
            iat = components.payload['iat']
            if isinstance(iat, int):
                iat_time = datetime.fromtimestamp(iat, tz=timezone.utc)
                decoded_info['issued_at'] = {
                    'timestamp': iat,
                    'datetime': iat_time.isoformat()
                }
        
        if 'nbf' in components.payload:
            nbf = components.payload['nbf']
            if isinstance(nbf, int):
                nbf_time = datetime.fromtimestamp(nbf, tz=timezone.utc)
                decoded_info['not_before'] = {
                    'timestamp': nbf,
                    'datetime': nbf_time.isoformat(),
                    'valid': nbf <= datetime.now(timezone.utc).timestamp()
                }
        
        if decoded_info:
            response.decoded_info = decoded_info
        
        # Verify signature if public key is provided
        if request.public_key:
            algorithm = components.header.get('alg')
            
            if algorithm not in SUPPORTED_ALGORITHMS:
                response.signature_valid = False
                response.error = f"Unsupported algorithm: {algorithm}"
                return response
            
            try:
                # Load public key
                rsa_key = CryptoPlus.loads(request.public_key)
                
                # Extract key information
                modulus = rsa_key.public_key.n
                key_bit_length = modulus.bit_length()
                
                # Add key info to decoded_info
                if not decoded_info:
                    decoded_info = {}
                decoded_info['key_info'] = {
                    'modulus_bits': key_bit_length,
                    'modulus_bytes': (key_bit_length + 7) // 8
                }
                response.decoded_info = decoded_info
                
                # Get hash algorithm and signature scheme
                hash_class, sig_scheme = SUPPORTED_ALGORITHMS[algorithm]
                
                # Verify signature
                hash_obj = hash_class.new(components.message)
                
                try:
                    if sig_scheme == pkcs1_15:
                        pkcs1_15.new(rsa_key.public_key).verify(hash_obj, components.signature)
                    else:  # pss
                        pss.new(rsa_key.public_key).verify(hash_obj, components.signature)
                    response.signature_valid = True
                except (ValueError, TypeError):
                    response.signature_valid = False
                    
            except Exception as e:
                response.signature_valid = False
                response.error = f"Signature verification failed: {str(e)}"
        
        return response
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Validation failed: {str(e)}")


def main():
    """Main entry point for the web application."""
    import argparse
    import uvicorn
    
    parser = argparse.ArgumentParser(description="AJWT Web Application")
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to (default: 8000)')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload for development')
    
    args = parser.parse_args()
    
    print(f"🚀 Starting AJWT Web Application on http://{args.host}:{args.port}")
    print(f"📖 Open your browser and navigate to the URL above")
    print(f"Press CTRL+C to quit")
    
    uvicorn.run(
        "ajwt.web_app:app",
        host=args.host,
        port=args.port,
        reload=args.reload
    )


if __name__ == "__main__":
    main()
