"""
MCP server for YouTube audio extraction.
"""
import argparse
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

from app.core import AudioExtractor

mcp = FastMCP("YouTube Audio Extractor", json_response=True)


@mcp.tool()
def extract_audio(
    url: str,
    format: str = "mp3",
    output_path: Optional[str] = None,
    cookies_file: Optional[str] = None,
    cookies_from_browser: Optional[str] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
) -> dict:
    """
    Extract audio from a YouTube URL.

    Args:
        url: YouTube video URL
        format: Audio format ('mp3' or 'wav'), default is 'mp3'
        output_path: Optional output file path. If not provided, uses a temporary file.

    Returns:
        Dictionary with 'success', 'file_path', 'filename', and optional 'error' keys
    """
    try:
        extractor = AudioExtractor(
            cookies_file=Path(cookies_file).expanduser().resolve()
            if cookies_file
            else None,
            cookies_from_browser=cookies_from_browser,
            user_agent=user_agent,
            proxy=proxy,
        )

        if output_path:
            output_file = Path(output_path)
            filename = extractor.extract_audio_to_file(url, output_file, format)
            return {
                "success": True,
                "file_path": str(output_file),
                "filename": filename,
            }
        else:
            output_file, filename = extractor.extract_audio(url, format)
            return {
                "success": True,
                "file_path": str(output_file),
                "filename": filename,
            }
    except ValueError as e:
        return {
            "success": False,
            "error": f"Invalid input: {str(e)}",
        }
    except RuntimeError as e:
        return {
            "success": False,
            "error": f"Extraction failed: {str(e)}",
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
        }


@mcp.tool()
def extract_audio_to_file(
    url: str,
    output_path: str,
    format: str = "mp3",
    cookies_file: Optional[str] = None,
    cookies_from_browser: Optional[str] = None,
    user_agent: Optional[str] = None,
    proxy: Optional[str] = None,
) -> dict:
    """
    Extract audio from a YouTube URL and save to a specific file path.

    Args:
        url: YouTube video URL
        output_path: Target output file path
        format: Audio format ('mp3' or 'wav'), default is 'mp3'

    Returns:
        Dictionary with 'success', 'file_path', 'filename', and optional 'error' keys
    """
    try:
        extractor = AudioExtractor(
            cookies_file=Path(cookies_file).expanduser().resolve()
            if cookies_file
            else None,
            cookies_from_browser=cookies_from_browser,
            user_agent=user_agent,
            proxy=proxy,
        )
        output_file = Path(output_path)
        filename = extractor.extract_audio_to_file(url, output_file, format)
        return {
            "success": True,
            "file_path": str(output_file),
            "filename": filename,
        }
    except ValueError as e:
        return {
            "success": False,
            "error": f"Invalid input: {str(e)}",
        }
    except RuntimeError as e:
        return {
            "success": False,
            "error": f"Extraction failed: {str(e)}",
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
        }


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="YouTube Audio Extractor MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport to use (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host for SSE transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Bind port for SSE transport (default: 8000)",
    )
    return parser.parse_args(argv)


def run_server(transport: str, host: str, port: int) -> None:
    if transport == "stdio":
        mcp.run()
        return
    if transport == "sse":
        try:
            mcp.run(transport="sse", host=host, port=port)
        except TypeError:
            mcp.run(transport="sse")
        return
    raise ValueError(f"Unsupported transport: {transport}")


def main(argv: Optional[list[str]] = None) -> None:
    args = _parse_args(argv)
    run_server(args.transport, args.host, args.port)


if __name__ == "__main__":
    main()
