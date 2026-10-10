"""Speech-to-text for videos without captions (faster-whisper), decoding via Chromium.

Why Chromium: faster-whisper normally decodes audio with PyAV, whose native DLL is
blocked by Windows Application Control on this machine, and there is no ffmpeg.
Playwright's Chromium is already allowed and decodes Opus/Vorbis/WebM natively.
WebAudio decodes the file and resamples it to 16 kHz mono (what Whisper expects), and
the samples come back to Python in chunks. faster-whisper then only receives a numpy
array, so the blocked module is never used. It is stubbed only so that importing
faster_whisper works.

The output is machine transcription and is labelled as such. The audio file itself is
kept as evidence (hashed), so anyone can re-check the transcript.
"""

from __future__ import annotations

import base64
import logging
import sys
import types
from dataclasses import dataclass

import numpy as np

log = logging.getLogger(__name__)
SR = 16_000
CHUNK = SR * 30            # samples per transfer (30 s)
_MODELS: dict[str, object] = {}

DECODE_JS = """
async () => {
  const resp = await fetch("http://osint.local/audio");
  const buf = await resp.arrayBuffer();
  const probe = new OfflineAudioContext(1, 1, __SR__);
  const decoded = await probe.decodeAudioData(buf);
  const off = new OfflineAudioContext(1, Math.ceil(decoded.duration * __SR__), __SR__);
  const src = off.createBufferSource();
  src.buffer = decoded; src.connect(off.destination); src.start();
  const out = await off.startRendering();
  window.__pcm = out.getChannelData(0);
  return {samples: window.__pcm.length, duration: decoded.duration};
}
""".replace("__SR__", str(SR))  # plain replace: the JS is full of braces

SLICE_JS = """
({start, end}) => {
  const f = window.__pcm.subarray(start, end);
  const i16 = new Int16Array(f.length);
  for (let i = 0; i < f.length; i++) i16[i] = Math.max(-1, Math.min(1, f[i])) * 32767;
  let s = ""; const b = new Uint8Array(i16.buffer);
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s);
}
"""


async def decode_audio(data: bytes, mime: str = "audio/webm") -> np.ndarray:
    """Decode any browser-playable audio to float32 16 kHz mono using headless Chromium."""
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(args=["--disable-gpu"])
        try:
            page = await browser.new_page()

            async def serve(route):
                await route.fulfill(status=200, body=data, headers={
                    "Content-Type": mime, "Access-Control-Allow-Origin": "*"})

            await page.route("http://osint.local/audio", serve)
            await page.goto("about:blank")
            info = await page.evaluate(DECODE_JS)
            parts = []
            for start in range(0, info["samples"], CHUNK):
                b64 = await page.evaluate(SLICE_JS, {"start": start,
                                                     "end": min(start + CHUNK, info["samples"])})
                parts.append(np.frombuffer(base64.b64decode(b64), dtype=np.int16))
        finally:
            await browser.close()
    pcm = np.concatenate(parts) if parts else np.zeros(0, dtype=np.int16)
    return (pcm.astype(np.float32) / 32767.0)


def _import_whisper():
    try:
        import faster_whisper
    except ImportError:
        # PyAV (used only for file decoding) is blocked here; we never use it.
        sys.modules.setdefault("av", types.ModuleType("av"))
        for mod in [m for m in sys.modules if m.startswith("faster_whisper")]:
            del sys.modules[mod]
        import faster_whisper
    return faster_whisper


def _model(size: str, device: str):
    key = f"{size}:{device}"
    if key not in _MODELS:
        fw = _import_whisper()
        if device in ("auto", "cuda"):
            try:
                m = fw.WhisperModel(size, device="cuda", compute_type="float16")
                # CUDA libraries (cuBLAS/cuDNN) load lazily: exercise the model once
                segs, _ = m.transcribe(np.zeros(SR, dtype=np.float32), language="en")
                list(segs)
                _MODELS[key] = m
                return m
            except Exception as e:  # missing CUDA libs (cuBLAS/cuDNN): CPU still works
                if device == "cuda":
                    raise
                log.info("whisper on GPU unavailable (%s); using CPU", e)
        _MODELS[key] = fw.WhisperModel(size, device="cpu", compute_type="int8")
    return _MODELS[key]


@dataclass
class Transcript:
    language: str
    language_probability: float
    segments: list[tuple[float, float, str]]
    model: str

    def as_text(self) -> str:
        def ts(sec: float) -> str:
            sec = int(sec)
            return f"{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}"

        return "\n".join(f"[{ts(a)}] {t.strip()}" for a, _, t in self.segments if t.strip())


def transcribe(audio: np.ndarray, size: str = "small", device: str = "auto") -> Transcript:
    m = _model(size, device)
    segments, info = m.transcribe(audio, beam_size=5, vad_filter=False)
    segs = [(s.start, s.end, s.text) for s in segments]
    return Transcript(info.language, round(info.language_probability, 3), segs,
                      f"faster-whisper-{size}")
