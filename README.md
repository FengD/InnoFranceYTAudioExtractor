## YouTube Audio Extractor (MP3)

Paste a YouTube link in the web UI and download the extracted audio as an **MP3**.

![App screenshot](docs/example.png)

### Requirements

- Python 3.10+
- `ffmpeg` installed on your system (required for MP3 conversion)
- Python packaging tools (`pip`, `venv`) available on your system

Install ffmpeg on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y ffmpeg
```

If you don't have `pip` / `venv`:

```bash
sudo apt update
sudo apt install -y python3-pip python3-venv
```

### Setup

```bash
cd /home/ding/Documents/youtube_extractor
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open:

- `http://localhost:8000`

### API (curl)

Health check:

```bash
curl -s http://localhost:8000/api/health
```

### Logging / audit trail

The app logs **who** made the request, **what** happened, and whether it **succeeded or failed**.

- **Request correlation**: every response includes `X-Request-Id` (you can also send your own `X-Request-Id`)
- **Who (caller identity)**: send `X-Client-Id: my-service` (preferred) or `X-Api-Key: ...` (only partially logged)
- **Where logs go**: stdout + rotating file at `./logs/app.log` (configurable via env)

Environment variables:

- **LOG_LEVEL**: `DEBUG|INFO|WARNING|ERROR` (default `INFO`)
- **LOG_FORMAT**: `json|text` (default `json`)
- **LOG_FILE**: path (default `./logs/app.log`)
- **TRUST_PROXY_HEADERS**: set to `1` if running behind a proxy and you want to trust `X-Forwarded-For`

Download MP3 via **POST JSON** (most reliable):

```bash
curl -L -X POST http://localhost:8000/api/extract \
  -H 'Content-Type: application/json' \
  -H 'X-Client-Id: my-cli' \
  -d '{"url":"https://www.youtube.com/watch?v=VIDEO_ID"}' \
  -OJ
```

Download MP3 via **GET** with URL encoding (curl-friendly):

```bash
curl -L -G http://localhost:8000/api/extract \
  --data-urlencode "url=https://www.youtube.com/watch?v=VIDEO_ID" \
  -OJ
```

Download MP3 via **POST form**:

```bash
curl -L -X POST http://localhost:8000/api/extract/form \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "url=https://www.youtube.com/watch?v=VIDEO_ID" \
  -OJ
```

### Notes

- This app uses `yt-dlp` to download audio and `ffmpeg` to convert to MP3.
- Some videos may be unavailable due to region/age restrictions or DRM.

