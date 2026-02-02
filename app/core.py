"""
Core audio extraction module for YouTube URLs.
"""
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from yt_dlp import YoutubeDL


class _SilentLogger:
    def debug(self, msg): pass
    def info(self, msg): pass
    def warning(self, msg): pass
    def error(self, msg): pass



class AudioExtractor:
    """
    Core class for extracting audio from YouTube URLs.
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        cookies_file: Optional[Path] = None,
        cookies_from_browser: Optional[str] = None,
    ):
        """
        Initialize the audio extractor.

        Args:
            output_dir: Optional directory to save output files. If None, uses temp directory.
            cookies_file: Optional path to a Netscape cookies.txt file.
            cookies_from_browser: Optional browser name for yt-dlp cookiesfrombrowser.
            user_agent: Optional custom User-Agent.
            proxy: Optional proxy URL.
        """
        self.output_dir = output_dir
        self.cookies_file = cookies_file
        self.cookies_from_browser = cookies_from_browser

    @staticmethod
    def _resolve_path(value: Optional[str]) -> Optional[Path]:
        if not value:
            return None
        return Path(value).expanduser().resolve()

    def _cookie_options(self) -> dict:
        cookiefile = self.cookies_file or self._resolve_path(os.getenv("YT_COOKIES_FILE"))
        cookies_from_browser = self.cookies_from_browser or os.getenv(
            "YT_COOKIES_FROM_BROWSER"
        )

        options: dict[str, str] = {}
        if cookiefile:
            if not cookiefile.exists():
                raise ValueError(f"Cookies file not found: {cookiefile}")
            options["cookiefile"] = str(cookiefile)
            return options

        if cookies_from_browser:
            options["cookiesfrombrowser"] = cookies_from_browser
        return options

    def _base_ydl_opts(self) -> dict:
        opts = {
            "quiet": True,
            "no_warnings": True,
            "noplaylist": True,
            "retries": 3,
            "fragment_retries": 3,
            "logger": _SilentLogger(),
            "progress_hooks": [],
            "noprogress": True,
        }
        opts.update(self._cookie_options())
        return opts

    @staticmethod
    def _is_empty_download_error(error: Exception) -> bool:
        return "downloaded file is empty" in str(error).lower()

    @staticmethod
    def _with_android_player_client(ydl_opts: dict) -> dict:
        updated = dict(ydl_opts)
        extractor_args = dict(updated.get("extractor_args") or {})
        youtube_args = dict(extractor_args.get("youtube") or {})
        youtube_args.setdefault("player_client", ["android", "web"])
        extractor_args["youtube"] = youtube_args
        updated["extractor_args"] = extractor_args
        return updated


    @staticmethod
    def sanitize_filename(name: str, max_len: int = 120) -> str:
        """
        Sanitize a filename to be filesystem-safe.

        Args:
            name: Original filename
            max_len: Maximum length of the filename

        Returns:
            Sanitized filename
        """
        name = name.strip()
        name = re.sub(r"\s+", " ", name)
        name = re.sub(r"[^a-zA-Z0-9 \-_\.\(\)\[\]]+", "", name)
        name = name.strip(" .-_")
        if not name:
            name = "audio"
        return name[:max_len]

    @staticmethod
    def normalize_audio_format(value: Optional[str]) -> str:
        """
        Normalize and validate audio format.

        Args:
            value: Format string (mp3 or wav)

        Returns:
            Normalized format string

        Raises:
            ValueError: If format is not supported
        """
        fmt = (value or "mp3").strip().lower()
        if fmt not in {"mp3", "wav"}:
            raise ValueError("Format must be either 'mp3' or 'wav'.")
        return fmt

    def extract_audio(
        self, url: str, audio_format: str = "mp3", output_path: Optional[Path] = None
    ) -> Tuple[Path, str]:
        """
        Extract audio from a YouTube URL.

        Args:
            url: YouTube URL
            audio_format: Output format ('mp3' or 'wav')
            output_path: Optional output file path. If None, uses temp directory.

        Returns:
            Tuple of (output_file_path, filename)

        Raises:
            ValueError: If format is invalid or extraction fails
            RuntimeError: If ffmpeg is not available or extraction fails
        """
        audio_format = self.normalize_audio_format(audio_format)

        if output_path:
            output_dir = output_path.parent
            output_dir.mkdir(parents=True, exist_ok=True)
            use_temp = False
        elif self.output_dir:
            output_dir = self.output_dir
            output_dir.mkdir(parents=True, exist_ok=True)
            use_temp = False
        else:
            output_dir = Path(tempfile.mkdtemp(prefix="yt-extract-"))
            use_temp = True

        try:
            # First get metadata (title) without downloading
            with YoutubeDL(self._base_ydl_opts()) as ydl:
                info = ydl.extract_info(str(url), download=False)

            title = self.sanitize_filename(info.get("title") or "audio")
            if output_path:
                outtmpl = str(output_path)
            else:
                outtmpl = str(output_dir / f"{title}.%(ext)s")

            postprocessor = {
                "key": "FFmpegExtractAudio",
                "preferredcodec": audio_format,
            }
            if audio_format == "mp3":
                postprocessor["preferredquality"] = "192"

            ydl_opts = {
                **self._base_ydl_opts(),
                "format": "18",
                "outtmpl": outtmpl,
                "postprocessors": [postprocessor],
            }

            try:
                with YoutubeDL(ydl_opts) as ydl:
                    ydl.download([str(url)])
            except Exception as download_error:
                if not self._is_empty_download_error(download_error):
                    raise

                retry_opts = self._with_android_player_client(ydl_opts)
                try:
                    with YoutubeDL(retry_opts) as ydl:
                        ydl.download([str(url)])
                except Exception as retry_error:
                    raise RuntimeError(
                        "YouTube returned an empty file. This is often caused by bot checks, "
                        "age/region restrictions, or missing cookies. Try --cookies-from-browser "
                        "or --cookies-file."
                    ) from retry_error

            expected_output = (
                output_path if output_path else output_dir / f"{title}.{audio_format}"
            )
            if expected_output.exists() and expected_output.stat().st_size > 0:
                filename = expected_output.name
                return expected_output, filename

            output_file: Optional[Path] = None
            for p in output_dir.glob(f"*.{audio_format}"):
                if p.exists() and p.stat().st_size > 0:
                    output_file = p
                    break

            if not output_file:
                raise RuntimeError(
                    f"{audio_format.upper()} was not created. Is ffmpeg installed and available on PATH?"
                )

            filename = output_file.name
            return output_file, filename

        except Exception as e:
            if use_temp:
                shutil.rmtree(output_dir, ignore_errors=True)
            if isinstance(e, (ValueError, RuntimeError)):
                raise
            raise RuntimeError(f"Failed to extract audio: {str(e)}") from e

    def list_formats(self, url: str) -> list[dict]:
        """
        List available formats for a YouTube URL.

        Args:
            url: YouTube URL

        Returns:
            List of format dictionaries from yt-dlp
        """
        with YoutubeDL(self._base_ydl_opts()) as ydl:
            info = ydl.extract_info(str(url), download=False)
        return list(info.get("formats") or [])

    def extract_audio_to_file(
        self, url: str, output_file: Path, audio_format: str = "mp3"
    ) -> str:
        """
        Extract audio to a specific file path.

        Args:
            url: YouTube URL
            output_file: Target output file path
            audio_format: Output format ('mp3' or 'wav')

        Returns:
            Filename (basename of output_file)

        Raises:
            ValueError: If format is invalid
            RuntimeError: If extraction fails
        """
        _, filename = self.extract_audio(url, audio_format, output_path=output_file)
        return filename

    @staticmethod
    def check_cookie_file(cookie_file: Path) -> dict:
        """
        Lightweight validation for a Netscape cookies.txt file.
        """
        if not cookie_file.exists():
            return {"ok": False, "reason": "missing_file", "detail": "Cookie file not found."}

        try:
            content = cookie_file.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return {"ok": False, "reason": "read_error", "detail": str(e)}

        domains = set()
        names = set()
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 7:
                continue
            domain = parts[0].lstrip(".").lower()
            name = parts[5].strip()
            if domain:
                domains.add(domain)
            if name:
                names.add(name)

        if not domains:
            return {
                "ok": False,
                "reason": "empty",
                "detail": "No cookies parsed from file.",
            }

        youtube_domains = [d for d in domains if "youtube.com" in d or "google.com" in d]
        if not youtube_domains:
            return {
                "ok": False,
                "reason": "no_youtube_cookies",
                "detail": "No youtube.com/google.com cookies found in file.",
            }

        required = {
            "SAPISID",
            "SID",
            "HSID",
            "SSID",
            "__Secure-1PSID",
            "__Secure-3PSID",
            "YSC",
            "VISITOR_INFO1_LIVE",
        }
        missing = sorted(required - names)
        if missing:
            return {
                "ok": False,
                "reason": "missing_login_cookies",
                "detail": f"Missing cookies: {', '.join(missing)}",
            }

        return {
            "ok": True,
            "reason": "ok",
            "detail": "Cookie file looks like a logged-in export.",
        }

    def diagnose_access(self, url: str) -> dict:
        """
        Diagnose whether the current cookie settings can access the URL.

        Returns:
            Dict with keys: ok (bool), reason (str), detail (str)
        """
        try:
            with YoutubeDL(self._base_ydl_opts()) as ydl:
                info = ydl.extract_info(str(url), download=False)
            title = info.get("title") if isinstance(info, dict) else None
            return {
                "ok": True,
                "reason": "ok",
                "detail": f"Accessible. Title: {title}" if title else "Accessible.",
            }
        except Exception as e:
            message = str(e)
            lowered = message.lower()
            reason = "unknown"
            if "sign in" in lowered or "login" in lowered:
                reason = "auth_required"
            elif "bot" in lowered or "not a bot" in lowered:
                reason = "bot_check"
            elif "unavailable" in lowered or "not available" in lowered:
                reason = "not_available"
            return {"ok": False, "reason": reason, "detail": message}


def extract_audio(url: str, audio_format: str = "mp3", output_dir: Optional[Path] = None) -> Tuple[Path, str]:
    """
    Convenience function to extract audio from a YouTube URL.

    Args:
        url: YouTube URL
        audio_format: Output format ('mp3' or 'wav')
        output_dir: Optional directory to save output. If None, uses temp directory.

    Returns:
        Tuple of (output_file_path, filename)

    Raises:
        ValueError: If format is invalid
        RuntimeError: If extraction fails
    """
    extractor = AudioExtractor(output_dir=output_dir)
    return extractor.extract_audio(url, audio_format)
