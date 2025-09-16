# Google Authenticator MCP

Google Authenticator MCP（Model Context Protocol）服务，提供 TOTP 验证码生成、otpauth URL 解析和 Google Authenticator 迁移 URL 解析功能。

## 🚀 功能特性

### 核心功能
- **迁移 URL 解析**：解析 `otpauth-migration://offline?data=...` 格式的 Google Authenticator 迁移链接
- **TOTP 验证码生成**：支持从密钥或 otpauth URL 生成时间基于的一次性密码
- **批量处理**：从迁移 URL 批量解析并生成所有账户的验证码

### 支持的算法和格式
- **哈希算法**：SHA1, SHA256, SHA512, MD5
- **验证码位数**：6位或8位数字
- **时间周期**：可配置的时间间隔（默认30秒）
- **OTP类型**：主要支持 TOTP（时间基于），部分支持 HOTP（计数基于）

## 🛠️ 使用方法

### 启动 MCP 服务

#### 快速启动 (STDIO 模式)

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

### 可用的 MCP 工具

服务提供以下 MCP 工具函数：

#### 1. `parse_migration_url`
解析 Google Authenticator 迁移 URL
```json
{
  "migration_url": "otpauth-migration://offline?data=..."
}
```

#### 2. `generate_all_tokens_from_migration`
从迁移 URL 批量生成所有账户的验证码
```json
{
  "migration_url": "otpauth-migration://offline?data=..."
}
```

#### 3. `generate_totp_token`
生成 TOTP 验证码
```json
{
  "secret_or_url": "ABCDEF..."
}
```

## 📋 配置选项

### 命令行参数
- `--transport`：传输方式（`stdio` 或 `sse`，默认：stdio）
- `--port`：SSE 模式端口（默认：3001）
- `--log-level`：日志级别（DEBUG, INFO, WARNING, ERROR）

## 📚 技术原理

### Google Authenticator 迁移格式
Google Authenticator 的迁移数据使用 Protocol Buffers (protobuf) 格式编码，包含：
- OTP 参数（密钥、算法、位数等）
- 账户信息（名称、发行者）
- 批次信息（版本、大小、索引等）

### TOTP 算法实现
基于 RFC 6238 标准实现：
1. 使用当前时间戳除以时间周期
2. 应用 HMAC-SHA 算法计算哈希
3. 提取动态截断码
4. 生成指定位数的数字验证码

### 支持的URL格式
- **迁移URL**：`otpauth-migration://offline?data=<base64-encoded-protobuf>`
- **标准URL**：`otpauth://totp/Label?secret=SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30`

## 🙏 参考

- [dim13/otpauth](https://github.com/dim13/otpauth) - Protocol Buffers 解析参考
- [grahammitchell/google-authenticator](https://github.com/grahammitchell/google-authenticator) - Google Authenticator 算法参考
- [RFC 6238](https://tools.ietf.org/html/rfc6238) - TOTP 算法标准
