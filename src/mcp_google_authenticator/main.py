"""MCP服务器主程序."""
import argparse
import logging
from typing import Any, Literal

from semantic_kernel import Kernel

from .google_authenticator_plugin import GoogleAuthenticatorPlugin

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def validate_environment():
    """验证环境配置."""
    return True


def create_kernel() -> Kernel:
    """创建Semantic Kernel."""
    kernel = Kernel()
    
    # 添加Google Authenticator插件
    kernel.add_plugin(GoogleAuthenticatorPlugin(), plugin_name="google_authenticator")
    
    logger.info("Kernel初始化完成，已加载集成功能模块")
    return kernel


def parse_arguments():
    """解析命令行参数."""
    parser = argparse.ArgumentParser(description="运行MCP服务器")
    parser.add_argument(
        "--transport",
        type=str,
        choices=["sse", "stdio"],
        default="stdio",
        help="传输方式 (默认: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=3001,
        help="SSE传输端口 (SSE模式必需)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="日志级别 (默认: INFO)",
    )
    return parser.parse_args()


def run(transport: Literal["sse", "stdio"] = "stdio", port: int | None = None) -> None:
    """
    异步运行 MCP 任务执行服务器
    
    Args:
        transport: 传输协议，支持 "sse" 或 "stdio"
        port: SSE 服务器端口（仅在 transport="sse" 时使用）
    """
    try:
        from dotenv import load_dotenv
        
        # 加载环境变量
        load_dotenv()
        
        # 验证环境
        validate_environment()
        
        # 创建Kernel
        kernel = create_kernel()
        
        # 创建MCP服务器
        server = kernel.as_mcp_server(
            version="0.1.0",
            server_name="google_authenticator",
            instructions=(
                "Google Authenticator MCP服务器。提供TOTP验证码生成、"
                "otpauth URL解析和Google Authenticator迁移URL解析功能。"
                "支持从迁移链接批量导入账户并生成验证码。"
            )
        )
        
        # 启动服务器
        if transport == "sse" and port is not None:
            logger.info(f"启动SSE服务器，端口: {port}")
            
            import uvicorn
            from mcp.server.sse import SseServerTransport
            from starlette.applications import Starlette
            from starlette.routing import Mount, Route

            sse = SseServerTransport("/messages/")

            async def handle_sse(request):
                async with sse.connect_sse(request.scope, request.receive, request._send) as (read_stream, write_stream):
                    await server.run(read_stream, write_stream, server.create_initialization_options())

            starlette_app = Starlette(
                debug=True,
                routes=[
                    Route("/sse", endpoint=handle_sse),
                    Mount("/messages/", app=sse.handle_post_message),
                ],
            )

            uvicorn.run(starlette_app, host="0.0.0.0", port=port)  # nosec
        elif transport == "stdio":
            logger.info("启动STDIO服务器")
            
            import anyio
            from mcp.server.stdio import stdio_server

            async def handle_stdin(stdin: Any | None = None, stdout: Any | None = None) -> None:
                async with stdio_server() as (read_stream, write_stream):
                    await server.run(read_stream, write_stream, server.create_initialization_options())

            anyio.run(handle_stdin)
        
        else:
            raise ValueError("SSE模式需要指定端口号")
            
    except Exception as e:
        logger.error(f"服务器启动失败: {e}")
        raise


def main():
    """
    MCP 服务器入口函数
    
    解析命令行参数并启动相应的 MCP 服务器
    """
    args = parse_arguments()
    
    # 设置日志级别
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    run(transport=args.transport, port=args.port)


if __name__ == "__main__":
    main()