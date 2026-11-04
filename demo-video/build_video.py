#!/usr/bin/env python3
"""Build the 3-minute narrated OpsAI-B demo video (static frames, no zoom).

Pipeline: narration MP3s (edge-tts) -> demo data -> server screenshots
(headless Chrome) -> title/closing cards (PIL) -> MP4 assembly (ffmpeg).

Single source of narration: demo-video/voiceover-en.md in this directory.

Usage:
    .venv/bin/python demo-video/build_video.py
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUILD = HERE / "build"
OUT = HERE / "opsai-b-demo-3min-en-narrated.mp4"

VOICE = "en-US-AvaNeural"
WIDTH, HEIGHT = 1280, 720
TARGET_SECONDS = 180.0
TAIL_SECONDS = 0.6

sys.path.insert(0, str(ROOT))

DEMO_LOG = """\
2026-11-01T08:00:01Z INFO app-srv-12 webapp Started on port 8080
2026-11-01T08:00:02Z INFO app-srv-12 webapp Connected to db-primary status=ok
2026-11-01T08:00:03Z WARN app-srv-12 webapp Slow query 1234ms user=alice@example.com
2026-11-01T08:00:04Z INFO app-srv-12 webapp Health check ok latency=12ms
2026-11-01T08:00:05Z ERROR app-srv-12 webapp Failed password for bob from 10.1.2.3
2026-11-01T08:00:06Z INFO app-srv-12 webapp Retrying upstream request attempt=1
2026-11-01T08:00:07Z WARN app-srv-12 webapp Disk usage 87 percent on /var/log
2026-11-01T08:00:08Z INFO app-srv-12 webapp password=hunter2 login attempt user=bob
2026-11-01T08:00:09Z INFO app-srv-12 webapp Cache refresh finished keys=4210
2026-11-01T08:00:10Z ERROR app-srv-12 webapp Upstream timeout after 5000ms card=4111111111111111
2026-11-01T08:00:11Z INFO app-srv-12 webapp Worker pool scaled to 8
2026-11-01T08:00:12Z INFO app-srv-12 webapp Shutdown signal received code=0
"""


@dataclass
class Scene:
    """One narration scene with its visual."""

    key: str
    text: str
    visual: str  # title | closing | shot name


def parse_voiceover() -> list[Scene]:
    """Parse scenes from voiceover-en.md (order defines the film)."""
    text = (HERE / "voiceover-en.md").read_text(encoding="utf-8")
    blocks = re.split(r"^## .+$\n", text, flags=re.MULTILINE)[1:]
    visuals = ["title", "sessions", "workplace", "oql", "analysis",
               "execution", "audit", "admin", "closing"]
    scenes = []
    for key, block in zip(visuals, blocks, strict=True):
        words = " ".join(block.split())
        scenes.append(Scene(key=key, text=words, visual=key))
    return scenes


def narrate(scenes: list[Scene]) -> list[Path]:
    """Render one MP3 per scene; return audio paths."""
    BUILD.mkdir(exist_ok=True)
    paths = []
    for i, scene in enumerate(scenes):
        target = BUILD / f"audio-{i:02d}.mp3"
        if not target.exists():
            subprocess.run(
                [sys.executable, "-m", "edge_tts", "--voice", VOICE,
                 "--text", scene.text, "--write-media", str(target)],
                check=True, capture_output=True,
            )
        paths.append(target)
    return paths


def seed_data() -> tuple[str, str]:
    """Create demo session, ingest log, run mock analysis; return ids."""
    from fastapi.testclient import TestClient

    from opsai.api.main import create_app
    from opsai.app.config import Settings

    data_dir = BUILD / "data"
    data_dir.mkdir(exist_ok=True)
    log = data_dir / "demo.log"
    log.write_text(DEMO_LOG, encoding="utf-8")
    settings = replace(Settings.from_env(), data_dir=data_dir, dev_auth=True)
    client = TestClient(create_app(settings))
    sid = client.post("/api/v1/sessions", json={"name": "demo-incident"}).json()["id"]
    ingest = client.post(f"/api/v1/sessions/{sid}/ingest-file",
                         json={"path": str(log)}).json()
    assert ingest["added"] == 12, ingest
    preview = client.post(
        "/api/v1/analyses/preview",
        json={"session_id": sid, "oql": "level>=ERROR", "mode": "full",
              "provider": "mock", "model": "mock-analysis-v1"},
    ).json()
    analysis = client.post(
        "/api/v1/analyses",
        json={"stage_id": preview["stage_id"],
              "payload_sha256": preview["payload_sha256"]},
    ).json()
    return sid, analysis["id"]


def start_server() -> subprocess.Popen[bytes]:
    """Start the app server over the demo data dir."""
    env = {
        "OPSAI_DATA_DIR": str(BUILD / "data"),
        "OPSAI_HOST": "127.0.0.1",
        "OPSAI_PORT": "8099",
        "OPSAI_LANGUAGE": "en",
        "OPSAI_DEV_AUTH": "1",
        "PATH": "/usr/bin:/bin",
    }
    log = (BUILD / "server.log").open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(ROOT / ".venv/bin/opsai"), "server"],
        env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    for _ in range(90):
        try:
            urllib.request.urlopen("http://127.0.0.1:8099/api/v1/health/live",
                                   timeout=2)
            return proc
        except OSError:
            time.sleep(1)
    proc.terminate()
    raise SystemExit("server did not start (see build/server.log)")


def screenshot(url: str, target: Path) -> None:
    """Capture one headless-Chrome screenshot."""
    subprocess.run(
        ["google-chrome", "--headless", "--no-sandbox", "--disable-gpu",
         "--hide-scrollbars", f"--window-size={WIDTH},{HEIGHT}",
         "--virtual-time-budget=8000", f"--screenshot={target}", url],
        check=True, capture_output=True, timeout=120,
    )


def capture_shots(sid: str, aid: str) -> None:
    """Screenshot all UI pages used by the film."""
    base = "http://127.0.0.1:8099"
    shots = {
        "sessions": f"{base}/",
        "workplace": f"{base}/session/{sid}",
        "oql": f"{base}/session/{sid}?oql=level%3E%3DERROR",
        "analysis": f"{base}/analysis?session_id={sid}",
        "execution": f"{base}/execution?analysis_id={aid}",
        "audit": f"{base}/audit",
        "admin": f"{base}/admin",
    }
    for name, url in shots.items():
        target = BUILD / f"shot-{name}.png"
        if not target.exists():
            screenshot(url, target)


def make_card(lines: list[tuple[str, int]], target: Path) -> None:
    """Render a centered title/closing card."""
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", (WIDTH, HEIGHT), (25, 43, 74))
    draw = ImageDraw.Draw(img)

    def font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
        for candidate in (
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ):
            try:
                return ImageFont.truetype(candidate, size)
            except OSError:
                continue
        return ImageFont.load_default()

    heights = [font(size).getbbox(line)[3] for line, size in lines]
    y = (HEIGHT - sum(heights) - 30 * (len(lines) - 1)) // 2
    for (line, size), height in zip(lines, heights, strict=True):
        fnt = font(size)
        width = fnt.getbbox(line)[2]
        draw.text(((WIDTH - width) // 2, y), line, font=fnt, fill="white")
        y += height + 30
    img.save(target)


def make_cards() -> None:
    """Render title and closing cards."""
    title = BUILD / "card-title.png"
    if not title.exists():
        make_card([("OpsAI", 120), ("variant B — Meta Model API", 54),
                   ("AI assistant for log analysis and guided remediation", 34)],
                  title)
    closing = BUILD / "card-closing.png"
    if not closing.exists():
        make_card([("OpsAI variant B — 0.1.0", 64),
                   ("366 tests passing · Meta only", 44),
                   ("github.com/RaviSileb/OpsAI-B", 44),
                   ("Thanks for watching", 54)],
                  closing)


def media_duration(ffmpeg: str, path: Path) -> float:
    """Return media duration in seconds via ffmpeg stderr."""
    proc = subprocess.run([ffmpeg, "-i", str(path)], capture_output=True, text=True)
    match = re.search(r"Duration: (\d+):(\d+):([\d.]+)", proc.stderr)
    if not match:
        raise SystemExit(f"cannot read duration of {path}")
    hours, minutes, seconds = match.groups()
    return int(hours) * 3600 + int(minutes) * 60 + float(seconds)


def visual_for(scene: Scene) -> Path:
    """Return the still image for a scene."""
    if scene.visual == "title":
        return BUILD / "card-title.png"
    if scene.visual == "closing":
        return BUILD / "card-closing.png"
    return BUILD / f"shot-{scene.visual}.png"


def assemble(ffmpeg: str, scenes: list[Scene], audios: list[Path]) -> None:
    """Encode one clip per scene and concat into the final MP4."""
    durations = [media_duration(ffmpeg, audio) + TAIL_SECONDS for audio in audios]
    gap = TARGET_SECONDS - sum(durations)
    extra = [0.0] * len(durations)
    if gap > 0:
        per_scene = min(gap / len(durations), 3.0)
        extra = [per_scene] * len(durations)
        durations = [d + per_scene for d in durations]
        durations[-1] += max(0.0, TARGET_SECONDS - sum(durations))
    clips = []
    for i, (scene, audio, duration) in enumerate(zip(scenes, audios, durations,
                                                    strict=True)):
        clip = BUILD / f"clip-{i:02d}.mp4"
        subprocess.run(
            [ffmpeg, "-y", "-v", "error", "-loop", "1", "-framerate", "2",
             "-i", str(visual_for(scene)), "-i", str(audio),
             "-filter_complex", f"[1:a]apad,atrim=0:{duration:.2f}[a]",
             "-map", "0:v", "-map", "[a]", "-t", f"{duration:.2f}",
             "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac",
             "-b:a", "128k", str(clip)],
            check=True,
        )
        clips.append(clip)
    lst = BUILD / "concat.txt"
    lst.write_text("".join(f"file '{c}'\n" for c in clips), encoding="utf-8")
    subprocess.run(
        [ffmpeg, "-y", "-v", "error", "-f", "concat", "-safe", "0",
         "-i", str(lst), "-c", "copy", str(OUT)],
        check=True,
    )
    total = media_duration(ffmpeg, OUT)
    print(f"extra tail per scene: {[f'{e:.1f}s' for e in extra]}")
    print(f"wrote {OUT} ({OUT.stat().st_size / 1e6:.1f} MB, {total:.0f}s)")


def main() -> None:
    """Run the full video pipeline."""
    from imageio_ffmpeg import get_ffmpeg_exe

    ffmpeg = get_ffmpeg_exe()
    scenes = parse_voiceover()
    print(f"scenes: {len(scenes)}, words: {sum(len(s.text.split()) for s in scenes)}")
    audios = narrate(scenes)
    sid, aid = seed_data()
    print(f"demo session={sid} analysis={aid}")
    proc = start_server()
    try:
        capture_shots(sid, aid)
    finally:
        proc.terminate()
        proc.wait(timeout=20)
    make_cards()
    assemble(ffmpeg, scenes, audios)


if __name__ == "__main__":
    main()
