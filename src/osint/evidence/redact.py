"""Face redaction for exported screenshots (OpenCV 5 YuNet face detector, runs locally).

It protects uninvolved people when evidence bundles are shared. The redacted copy is a
new file with its own SHA-256, and the bundle records which original (by hash) it came
from and how. The original stays untouched in the evidence store.

The YuNet model (opencv_zoo, ~230 KB) is downloaded once into data/models and must
match the pinned SHA-256, otherwise it is refused. Detection is good but not perfect
(tiny, heavily occluded or stylised faces can be missed): look at a redacted bundle
before sharing it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

MODEL_URL = ("https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/"
             "face_detection_yunet_2023mar.onnx")
MODEL_SHA256 = "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4"
METHOD = "opencv YuNet (face_detection_yunet_2023mar), gaussian blur"
TILE = 1600          # detect on tiles: full-page screenshots can be 10k+ px tall


@dataclass
class Redaction:
    data: bytes
    regions: int


def model_path(models_dir: Path, proxy: str | None = None) -> Path:
    path = models_dir / "face_detection_yunet_2023mar.onnx"
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == MODEL_SHA256:
        return path
    import httpx

    data = httpx.get(MODEL_URL, follow_redirects=True, timeout=60, proxy=proxy).content
    if hashlib.sha256(data).hexdigest() != MODEL_SHA256:
        raise ValueError("face model download does not match the pinned SHA-256; refusing it")
    models_dir.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def redact_faces(png: bytes, model: Path, score: float = 0.6) -> Redaction:
    import cv2
    import numpy as np

    img = cv2.imdecode(np.frombuffer(png, dtype=np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("not an image")
    h_img, w_img = img.shape[:2]
    det = cv2.FaceDetectorYN.create(str(model), "", (min(w_img, TILE), min(h_img, TILE)),
                                    score, 0.3, 5000)
    boxes = []
    step = TILE - 200                                      # overlap so faces on seams count
    for y in range(0, max(1, h_img - 200), step):
        for x in range(0, max(1, w_img - 200), step):
            tile = img[y:y + TILE, x:x + TILE]
            det.setInputSize((tile.shape[1], tile.shape[0]))
            _, faces = det.detect(tile)
            if faces is not None:
                boxes += [(int(f[0]) + x, int(f[1]) + y, int(f[2]), int(f[3])) for f in faces]
    for x, y, w, h in boxes:
        pad_x, pad_y = w // 3, h // 3                      # cover hair and edges too
        x0, y0 = max(0, x - pad_x), max(0, y - pad_y)
        x1, y1 = min(w_img, x + w + pad_x), min(h_img, y + h + pad_y)
        if x1 <= x0 or y1 <= y0:
            continue
        roi = img[y0:y1, x0:x1]
        k = max(31, (min(roi.shape[:2]) // 2) | 1)         # odd kernel, strong blur
        img[y0:y1, x0:x1] = cv2.GaussianBlur(roi, (k, k), 0)
    ok, buf = cv2.imencode(".png", img)
    if not ok:
        raise ValueError("encoding failed")
    return Redaction(buf.tobytes(), len(boxes))
