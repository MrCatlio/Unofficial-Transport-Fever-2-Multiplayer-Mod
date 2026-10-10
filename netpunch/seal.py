#!/usr/bin/env python3
"""
seal.py -- encrypt + authenticate every NP1 DATA frame.

The lobby CODE now carries a random 12-byte session secret (connect.py). Every
member derives the same key from it, plus an OPTIONAL password typed in the
menu; frames are then sealed as NP1 type 'E' instead of plain 'D':

    E-frame payload = nonce(12) || ChaCha20-Poly1305 ciphertext and tag
    nonce           = sender salt(4, random per process) || counter(8)

The control/game path uses a standard AEAD construction. Bulk save chunks keep
the separate HMAC-only path for throughput; they are independently hash-checked
before installation. The lobby version gate prevents old peers from sharing a
session with this framing.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SECRET_LEN = 12
NONCE_LEN = 8
TAG_LEN = 16
AEAD_NONCE_LEN = 12
WINDOW = 1024   # frames per sender salt (64 until 2026-09-22: see Sealer.sign)
AEAD_DOMAIN = b"tpf2mp-np1-edata-v2"

# Domain separator for sign()/unsign(). Without it a signed (plaintext) frame
# and a sealed (encrypted) frame share one MAC construction, so either could
# be presented to the other's verifier. The transport already tells them apart
# by frame type, but the crypto should not depend on that.
SIGN_DOMAIN = b"sign"


def derive_key(secret: bytes, password: str = "") -> bytes:
    return hashlib.sha256(b"tpf2mp-seal-v1|" + bytes(secret) + b"|"
                          + (password or "").encode("utf-8")).digest()


class Sealer:
    """One per process; shared by every socket owner (thread-safe counter)."""

    def __init__(self, key: bytes):
        self.aead_key = hashlib.sha256(key + b"|aead-chacha20poly1305-v2").digest()
        self.mac_key = hashlib.sha256(key + b"|mac").digest()
        self.salt = os.urandom(4)
        self.ctr = 0
        self.bulk_salt = os.urandom(4)   # sign()'s own nonce space: its own replay window at the receiver
        self.bulk_ctr = 0
        self._lock = threading.Lock()
        self._windows = {}          # AEAD sender salt -> [highest, bitmap]
        self._bulk_windows = {}     # signed-bulk sender salt -> [highest, bitmap]
        self.rejected = 0
        self.too_old = 0            # of those: outside the replay window (logged by the lobby)

    def seal(self, plain: bytes) -> bytes:
        with self._lock:
            self.ctr += 1
            if self.ctr > 0xFFFFFFFFFFFFFFFF:
                self.salt = os.urandom(4)
                self.ctr = 1
            nonce = self.salt + struct.pack("!Q", self.ctr)
        encrypted = ChaCha20Poly1305(self.aead_key).encrypt(nonce, plain, AEAD_DOMAIN)
        return nonce + encrypted

    # -- authenticate-only (no encryption) ---------------------------------- #
    # For BULK SAVE CHUNKS only. Same nonce, same replay window, same tag --
    # the only thing dropped is the keystream XOR.
    #
    # WHY: the keystream is one SHA-256 per 32 bytes of payload, which measures
    # 60 MB/s, against 614 MB/s for the HMAC that protects it. Sealing a 642 MB
    # save for two peers is ~25 s of pure CPU; signing it is ~2 s. On a save
    # transfer that is the difference between minutes and seconds.
    #
    # WHAT THIS COSTS: confidentiality of the save file, and nothing else.
    # Authenticity and integrity are unchanged (same HMAC over nonce||payload),
    # replay is still rejected by the same window, and every file additionally
    # carries a SHA-256 that the receiver verifies before writing. An observer
    # on the wire could read the map you are playing. Control messages (join,
    # chat, roster, start) keep full encryption.
    #
    # Enabled per-frame by the caller, never globally: see TYPE_ADATA in
    # punch.py and _pack_data(bulk=True) in lobby.py.
    #
    # ITS OWN NONCE SPACE (2026-09-22). Bulk chunks used the control frames'
    # counter, so both shared one replay window at the receiver. Over Steam a
    # 32 KB chunk goes reliable and waits in Steam's queue behind megabytes of
    # others, while later pings, rosters and game frames (small, unreliable)
    # overtake it: once 64 newer frames were accepted, the chunk arrived "too
    # old" and was dropped without a word, and so was every re-send of it (each
    # queued the same way) -- chunk 0 never landed (0.6.1.22, base 0/4199).
    # A separate salt gives chunks a separate window (the receiver keys windows
    # on the salt), and WINDOW is wider for the reorder the rest may see.
    def sign(self, plain: bytes) -> bytes:
        with self._lock:
            self.bulk_ctr += 1
            if self.bulk_ctr > 0xFFFFFFFF:
                self.bulk_salt = os.urandom(4)
                self.bulk_ctr = 1
            nonce = self.bulk_salt + struct.pack("!I", self.bulk_ctr)
        tag = hmac.new(self.mac_key, SIGN_DOMAIN + nonce + plain,
                       hashlib.sha256).digest()[:TAG_LEN]
        return nonce + plain + tag

    def unsign(self, data: bytes):
        """-> plaintext, or None (bad tag / replay / malformed)."""
        if len(data) < NONCE_LEN + TAG_LEN:
            self.rejected += 1
            return None
        nonce, body, tag = data[:NONCE_LEN], data[NONCE_LEN:-TAG_LEN], data[-TAG_LEN:]
        want = hmac.new(self.mac_key, SIGN_DOMAIN + nonce + body,
                        hashlib.sha256).digest()[:TAG_LEN]
        if not hmac.compare_digest(want, tag):
            self.rejected += 1
            return None
        if not self._accept_nonce(nonce, self._bulk_windows, "!I"):
            return None
        return body

    # Replay window, shared by open() and unsign() so a frame of either kind
    # can only be accepted once per (sender salt, counter).
    def _accept_nonce(self, nonce: bytes, windows, counter_format: str) -> bool:
        counter_size = struct.calcsize(counter_format)
        if len(nonce) != 4 + counter_size:
            return False
        salt, ctr = nonce[:4], struct.unpack(counter_format, nonce[4:])[0]
        with self._lock:
            w = windows.get(salt)
            if w is None:
                windows[salt] = [ctr, 1]
                return True
            high, bits = w
            if ctr > high:
                shift = ctr - high
                w[0], w[1] = ctr, 1 if shift >= WINDOW else ((bits << shift) | 1) & ((1 << WINDOW) - 1)
                return True
            back = high - ctr
            if back >= WINDOW or (bits >> back) & 1:
                self.rejected += 1
                if back >= WINDOW:
                    self.too_old += 1
                return False                     # replayed or too old
            w[1] = bits | (1 << back)
            return True

    def open(self, data: bytes):
        """-> plaintext, or None (bad tag / replay / malformed)."""
        if len(data) < AEAD_NONCE_LEN + TAG_LEN:
            self.rejected += 1
            return None
        nonce, encrypted = data[:AEAD_NONCE_LEN], data[AEAD_NONCE_LEN:]
        try:
            plain = ChaCha20Poly1305(self.aead_key).decrypt(nonce, encrypted, AEAD_DOMAIN)
        except (InvalidTag, ValueError):
            self.rejected += 1
            return None
        if not self._accept_nonce(nonce, self._windows, "!Q"):
            return None
        return plain


def selftest():
    k = derive_key(os.urandom(SECRET_LEN), "pw")
    a, b = Sealer(k), Sealer(k)
    ok = True
    for size in (0, 1, 31, 32, 33, 1200, 4000):
        m = os.urandom(size)
        s = a.seal(m)
        if b.open(s) != m:
            ok = False; print(f"[seal] FAIL roundtrip size={size}")
    # tamper, replay, wrong key
    s = a.seal(b"hello")
    if b.open(s) != b"hello": ok = False
    if b.open(s) is not None: ok = False; print("[seal] FAIL replay accepted")
    t = bytearray(s); t[NONCE_LEN] ^= 1
    if b.open(bytes(t)) is not None: ok = False; print("[seal] FAIL tamper accepted")
    c = Sealer(derive_key(os.urandom(SECRET_LEN), "pw"))
    if c.open(a.seal(b"x")) is not None: ok = False; print("[seal] FAIL wrong key accepted")
    # reorder within the window is fine
    frames = [a.seal(bytes([i])) for i in range(10)]
    for f in reversed(frames):
        if b.open(f) is None: ok = False; print("[seal] FAIL reorder rejected")
    # sign/unsign: same guarantees minus confidentiality
    s2 = Sealer(k); v2 = Sealer(k)
    m = os.urandom(1200)
    sg = s2.sign(m)
    if m not in sg: ok = False; print("[seal] FAIL sign is supposed to be plaintext")
    if v2.unsign(sg) != m: ok = False; print("[seal] FAIL sign roundtrip")
    if v2.unsign(sg) is not None: ok = False; print("[seal] FAIL sign replay accepted")
    t2 = bytearray(s2.sign(m)); t2[NONCE_LEN] ^= 1
    if v2.unsign(bytes(t2)) is not None: ok = False; print("[seal] FAIL sign tamper accepted")
    if Sealer(derive_key(os.urandom(SECRET_LEN), "")).unsign(s2.sign(m)) is not None:
        ok = False; print("[seal] FAIL sign wrong key accepted")
    # a signed frame must NOT open as sealed, and vice versa
    if v2.open(s2.sign(m)) is not None: ok = False; print("[seal] FAIL signed frame verified as sealed")
    if Sealer(k).unsign(Sealer(k).seal(m)) is not None:
        ok = False; print("[seal] FAIL sealed frame verified as signed")
    # the 2^64 counter wrap must roll the salt
    w = Sealer(k)
    w.ctr = 0xFFFFFFFFFFFFFFFF
    salt0 = w.salt
    wrapped = w.seal(b"wrap")
    if w.salt == salt0 or w.ctr != 1:
        ok = False; print("[seal] FAIL counter wrap did not re-salt")
    if Sealer(k).open(wrapped) != b"wrap":
        ok = False; print("[seal] FAIL frame after wrap does not open")
    # A CHUNK OVERTAKEN BY CONTROL FRAMES (0.6.1.22 over Steam): signed first,
    # delivered after 2,000 frames sealed later -- it must still be taken, once
    snd, rcv = Sealer(k), Sealer(k)
    late = snd.sign(b"chunk 0")
    for i in range(2000):
        if rcv.open(snd.seal(b"ping %d" % i)) is None:
            ok = False; print("[seal] FAIL control frame rejected"); break
    if rcv.unsign(late) != b"chunk 0":
        ok = False; print("[seal] FAIL a chunk overtaken by later control frames was rejected")
    if rcv.unsign(late) is not None:
        ok = False; print("[seal] FAIL the overtaken chunk was accepted twice")
    # chunks reordered among themselves within WINDOW: all taken; far older: refused
    chunks = [snd.sign(bytes([i % 256])) for i in range(WINDOW + 5)]
    if any(rcv.unsign(f) is None for f in chunks[5:][::-1]):
        ok = False; print("[seal] FAIL chunk reorder within the window rejected")
    if rcv.unsign(chunks[0]) is not None:
        ok = False; print("[seal] FAIL a chunk older than the window was accepted")
    import time
    t0 = time.time(); n = 0
    while time.time() - t0 < 0.5:
        b.open(a.seal(b"x" * 1200)); n += 1
    print(f"[seal] {'PASS' if ok else 'FAIL'}: roundtrip/tamper/replay/reorder; "
          f"~{n * 1200 * 2 / 0.5 / 1e6:.0f} MB/s seal+open")
    return ok


if __name__ == "__main__":
    import sys
    sys.exit(0 if selftest() else 1)
