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


class AudioExtractor:
    """
    Core class for extracting audio from YouTube URLs.
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        cookies_file: Optional[Path] = None,
        cookies_from_browser: Optional[str] = None,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
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
        self.user_agent = user_agent
        self.proxy = proxy

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
        }
        opts.update(self._cookie_options())
        user_agent = self.user_agent or os.getenv("YT_USER_AGENT")
        if user_agent:
            opts["user_agent"] = user_agent
        proxy = self.proxy or os.getenv("YT_PROXY")
        if proxy:
            opts["proxy"] = proxy
        return opts

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
                "format": "bestaudio/best",
                "outtmpl": outtmpl,
                "postprocessors": [postprocessor],
            }

            with YoutubeDL(ydl_opts) as ydl:
                ydl.download([str(url)])

            # Find the output file
            output_file: Optional[Path] = None
            for p in output_dir.glob(f"*.{audio_format}"):
                output_file = p
                break

            if not output_file or not output_file.exists():
                raise RuntimeError(
                    f"{audio_format.upper()} was not created. Is ffmpeg installed and available on PATH?"
                )

            filename = f"{title}.{audio_format}"

            # If using temp directory, we'll return the temp file
            # The caller is responsible for cleanup if use_temp is True
            return output_file, filename

        except Exception as e:
            if use_temp:
                shutil.rmtree(output_dir, ignore_errors=True)
            if isinstance(e, (ValueError, RuntimeError)):
                raise
            raise RuntimeError(f"Failed to extract audio: {str(e)}") from e

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
