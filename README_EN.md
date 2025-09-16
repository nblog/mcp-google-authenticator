# Google Authenticator MCP

Google Authenticator MCP (Model Context Protocol) server providing TOTP token generation, otpauth URL parsing, and Google Authenticator migration URL parsing capabilities.

## 🚀 Features

### Core Functionality
- **Migration URL Parsing**: Parse `otpauth-migration://offline?data=...` format Google Authenticator migration links
- **TOTP Token Generation**: Generate Time-based One-Time Passwords from secrets or otpauth URLs
- **Batch Processing**: Parse migration URLs and generate tokens for all accounts in bulk

### Supported Algorithms and Formats
- **Hash Algorithms**: SHA1, SHA256, SHA512, MD5
- **Token Digits**: 6 or 8 digit codes
- **Time Period**: Configurable time intervals (default 30 seconds)
- **OTP Types**: Primary support for TOTP (Time-based), partial support for HOTP (Counter-based)

## 🛠️ Usage

### Starting the MCP Server

#### Quick Start (STDIO Mode)

```json
{
    "mcpServers": {
        "mcp-google-authenticator": {
            "command": "uvx",
            "args": [
                "--from",
                "mcp-google-authenticator@git+https://github.com/nblog/mcp-google-authenticator.git",
                "mcp-google-authenticator"
            ]
        }
    }
}
```

### Available MCP Tools

The server provides the following MCP tool functions:

#### 1. `parse_migration_url`
Parse Google Authenticator migration URLs
```json
{
  "migration_url": "otpauth-migration://offline?data=..."
}
```

#### 2. `generate_all_tokens_from_migration`
Generate tokens for all accounts from a migration URL
```json
{
  "migration_url": "otpauth-migration://offline?data=..."
}
```

#### 3. `generate_totp_token`
Generate TOTP tokens
```json
{
  "secret_or_url": "ABCDEF..."
}
```

## 📋 Configuration Options

### Command Line Arguments
- `--transport`: Transport method (`stdio` or `sse`, default: stdio)
- `--port`: SSE mode port (default: 3001)
- `--log-level`: Log level (DEBUG, INFO, WARNING, ERROR)

## 📚 Technical Details

### Google Authenticator Migration Format
Google Authenticator migration data uses Protocol Buffers (protobuf) encoding, containing:
- OTP parameters (secret, algorithm, digits, etc.)
- Account information (name, issuer)
- Batch information (version, size, index, etc.)

### TOTP Algorithm Implementation
Based on RFC 6238 standard:
1. Use current timestamp divided by time period
2. Apply HMAC-SHA algorithm to compute hash
3. Extract dynamic truncation code
4. Generate specified digit verification code

### Supported URL Formats
- **Migration URL**: `otpauth-migration://offline?data=<base64-encoded-protobuf>`
- **Standard URL**: `otpauth://totp/Label?secret=SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30`

## 🙏 References

- [dim13/otpauth](https://github.com/dim13/otpauth) - Protocol Buffers parsing reference
- [grahammitchell/google-authenticator](https://github.com/grahammitchell/google-authenticator) - Google Authenticator algorithm reference
- [RFC 6238](https://tools.ietf.org/html/rfc6238) - TOTP algorithm standard