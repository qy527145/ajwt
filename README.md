# AJWT - Advanced JWT Tools

高级 JWT 工具集,支持 RSA 密钥恢复攻击和 Web 图形界面。

## 功能特性

### 🔐 JWT 分析工具 (`ajwt`)
- JWT Token 解析和分析
- Header 和 Payload 解码
- 签名信息查看
- 时间戳验证和过期检查
- 支持多种签名算法识别

### 🔓 RSA 密钥恢复工具 (`ajwt_rsa`)
- 从多个 JWT Token 恢复 RSA 公钥
- 支持 RS256/RS384/RS512/PS256/PS384/PS512 算法
- 并行处理提高效率
- 自动验证恢复的密钥

### 🌐 Web 图形界面 (`ajwt_web`)
- **密钥管理**
  - 生成 RSA 密钥对 (2048/3072/4096 位)
  - 上传现有私钥
  - 自动提取公钥
- **JWT 生成**
  - 支持多种签名算法
  - 自定义 Header 和 Payload
  - 一键生成和复制
- **JWT 验证**
  - Token 解析
  - 签名验证
  - 时间戳解析
  - 过期检查

## 安装

### 使用 uv (推荐)

```bash
# 克隆仓库
git clone https://github.com/yourusername/ajwt.git
cd ajwt

# 同步依赖
uv sync

# 或直接安装
uv pip install .
```

### 使用 pip

```bash
pip install ajwt
```

## 快速开始

### 1. JWT 分析工具

```bash
# 交互模式
uv run ajwt

# 分析指定 Token
uv run ajwt --token "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**输出示例:**
```
================================================================================
JWT TOKEN ANALYSIS
================================================================================

📋 HEADER:
----------------------------------------
{
  "alg": "RS256",
  "typ": "JWT"
}

🔐 Algorithm: RS256
🔑 RSA-based signature (asymmetric key)

📦 PAYLOAD:
----------------------------------------
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}

📝 STANDARD CLAIMS:
----------------------------------------
  Subject: 1234567890
  Issued At: 2018-01-18 01:30:22 UTC (1516239022)

🔏 SIGNATURE:
----------------------------------------
  Length: 256 bytes (2048 bits)
```

### 2. RSA 密钥恢复工具

```bash
uv run ajwt_rsa
```

**使用流程:**
1. 输入至少 2 个使用相同 RSA 密钥签名的 JWT Token
2. 工具自动计算并恢复 RSA 公钥
3. 验证恢复的密钥是否有效

**输出示例:**
```
==================================================
ATTACK SUCCESSFUL!
==================================================
RSA Modulus (n):
25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987481896995098600

Public Key (PEM):
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pSjbSYZVebtTRBLxBz5H
...
-----END PUBLIC KEY-----
==================================================
```

### 3. Web 图形界面

```bash
# 使用默认配置 (127.0.0.1:8000)
uv run ajwt_web

# 指定主机和端口
uv run ajwt_web --host 0.0.0.0 --port 8080

# 开发模式 (启用自动重载)
uv run ajwt_web --reload
```

然后在浏览器中访问 `http://127.0.0.1:8000`

#### Web 界面功能

**密钥管理:**
1. 选择"生成密钥对"或"上传私钥"
2. 生成/上传后,公钥会自动填充到验证区域

**生成 JWT:**
1. 确保已加载私钥
2. 选择签名算法
3. 编辑 Header 和 Payload (JSON 格式)
4. 点击"生成 JWT"
5. 复制生成的 Token

**验证 JWT:**
1. 粘贴 JWT Token
2. 公钥会自动填充(如果已加载私钥)
3. 点击"验证 JWT"
4. 查看解析结果和签名验证状态

## API 接口

Web 应用提供以下 REST API:

### POST /api/generate-keypair
生成 RSA 密钥对

```json
// 请求
{
  "key_size": 2048
}

// 响应
{
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "key_size": 2048
}
```

### POST /api/extract-public-key
从私钥提取公钥

```json
// 请求
{
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n..."
}

// 响应
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

### POST /api/generate-jwt
生成 JWT Token

```json
// 请求
{
  "header": {"alg": "RS256", "typ": "JWT"},
  "payload": {"sub": "1234567890", "name": "John Doe"},
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
  "algorithm": "RS256"
}

// 响应
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### POST /api/validate-jwt
验证和解析 JWT Token

```json
// 请求
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n..."  // 可选
}

// 响应
{
  "valid": true,
  "header": {"alg": "RS256", "typ": "JWT"},
  "payload": {"sub": "1234567890", "name": "John Doe"},
  "signature_valid": true,
  "decoded_info": {
    "expiration": {
      "timestamp": 1735300000,
      "datetime": "2024-12-27T12:00:00+00:00",
      "expired": false
    }
  }
}
```

## 支持的算法

- **RS256**: RSASSA-PKCS1-v1_5 with SHA-256
- **RS384**: RSASSA-PKCS1-v1_5 with SHA-384
- **RS512**: RSASSA-PKCS1-v1_5 with SHA-512
- **PS256**: RSASSA-PSS with SHA-256
- **PS384**: RSASSA-PSS with SHA-384
- **PS512**: RSASSA-PSS with SHA-512

## 依赖项

- Python >= 3.8
- crypto-plus >= 1.0.6
- gmpy2 >= 2.2.1
- fastapi >= 0.104.0 (Web 界面)
- uvicorn >= 0.24.0 (Web 界面)
- pydantic >= 2.0.0 (Web 界面)

## 开发

```bash
# 克隆仓库
git clone https://github.com/yourusername/ajwt.git
cd ajwt

# 安装开发依赖
uv sync

# 运行测试
uv run python test_jwt_tools.py

# 启动 Web 应用 (开发模式)
uv run ajwt_web --reload
```

## 安全注意事项

1. **密钥安全**: 
   - 私钥应妥善保管,不要泄露
   - Web 界面的密钥仅在浏览器会话中保存
   - 生产环境建议使用 HTTPS

2. **密钥长度**: 
   - 推荐使用至少 2048 位的 RSA 密钥
   - 更高安全性场景使用 4096 位

3. **Token 过期**: 
   - 生成 JWT 时设置合理的过期时间 (`exp` 字段)
   - 定期轮换密钥

4. **RSA 密钥恢复**: 
   - 此工具用于安全研究和测试
   - 不要用于非法用途

## 故障排除

### 端口被占用
```bash
uv run ajwt_web --port 8080
```

### 依赖安装失败
```bash
uv sync --reinstall
```

### 签名验证失败
- 确保公钥与私钥匹配
- 检查算法是否一致
- 确认 Token 未被修改

## 示例

### JWT Payload 示例

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "email": "john@example.com",
  "iat": 1516239022,
  "exp": 1735300000,
  "nbf": 1516239022,
  "roles": ["admin", "user"],
  "permissions": ["read", "write"]
}
```

### 使用 Python API

```python
from ajwt.jwt_parser import JWTParser
from ajwt.jwt_tool import JWTAnalyzer

# 解析 JWT
token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
components = JWTParser.parse(token)

print(components.header)
print(components.payload)
print(components.signature.hex())

# 分析 JWT
analyzer = JWTAnalyzer()
analyzer.analyze_token(token)
```

## 更新日志

### v0.3.0 (2024-11-27)
- ✨ 新增 Web 图形界面
- ✨ 支持密钥对生成和管理
- ✨ 支持 JWT 生成和验证
- ✨ 自动提取公钥功能
- 🎨 优化界面布局为单列流式设计
- 📝 更新文档

### v0.2.2
- 🐛 修复 JWT 解析问题
- ⚡ 优化性能

### v0.2.0
- ✨ 添加 RSA 密钥恢复工具
- ✨ 支持多种 RSA 签名算法
- ⚡ 并行处理提高效率

### v0.1.0
- 🎉 初始版本
- ✨ JWT 解析和分析功能

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request!

## 作者

wmymz - wmymz@icloud.com

## 致谢

- [crypto-plus](https://github.com/qiaoxin111/crypto-plus) - 加密工具库
- [FastAPI](https://fastapi.tiangolo.com/) - Web 框架
- [gmpy2](https://github.com/aleaxit/gmpy) - 高精度数学运算
