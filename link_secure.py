# link_secure.py
# 安全的 Link 实现：尝试使用 AES-GCM + PBKDF2（cryptography 优先，回退 PyCryptodome），
# 兼容旧格式（XOR+HMAC）。在没有任何 crypto 库时，会回退到旧写法（并记录警告）。

import os
import json
import base64
import time
import struct
import hashlib
import hmac
import warnings
from typing import Optional

# 尝试导入 cryptography 的 AESGCM
_have_cryptography = False
_have_pycrypto = False
_AESGCM = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _AESGCM = 'cryptography'
    _have_cryptography = True
except Exception:
    try:
        # PyCryptodome 的 GCM API
        from Crypto.Cipher import AES
        _AESGCM = 'pycryptodome'
        _have_pycrypto = True
    except Exception:
        _AESGCM = None

# 版本标识
OLD_VERSION = b"\x01\x02"  # 与原实现保持一致
NEW_VERSION = b"\x02\x00"
KDF_ITER = 100000

def atomic_write_json(path: str, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            # 某些手机平台对 fsync 支持不完全，尽力而为
            pass
    os.replace(tmp, path)


class Link:
    """Link: 支持新安全格式（AES-GCM）与旧格式（XOR+HMAC）的双读。

    写入策略：优先使用可用的 AEAD backend（cryptography 或 PyCryptodome），
    若都不可用，则回退到旧实现写入（并发出警告）。

    读取：能识别并解码 OLD_VERSION 和 NEW_VERSION。
    可选参数 migrate_on_read：若读到旧格式并成功解密，可选择性写入新格式（生成新 id）。
    """

    VERSION = NEW_VERSION

    def __init__(self, store_dir: str = "./link_store"):
        self.store_dir = store_dir
        os.makedirs(self.store_dir, exist_ok=True)
        if not (_have_cryptography or _have_pycrypto):
            warnings.warn("No AES-GCM backend available (cryptography or pycryptodome). Will fall back to old insecure write if asked.")

    def _derive_key(self, pwd: str, salt: bytes) -> bytes:
        # PBKDF2 -> 32 bytes key for AES-256
        return hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, KDF_ITER, dklen=32)

    # --- old insecure implementation (保留以兼容历史、并作为最后回退) ---
    def _old_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        # 使用 XOR keystream + HMAC(sig) 的布局： VERSION(2) + length(4) + iv(12) + encrypted + mac(32)
        # 这是与旧代码相兼容的实现（请保证与历史实现一致）
        length = len(plaintext)
        # 旧实现不使用 iv 真正的作用，这里为兼容保留 12 bytes
        iv = os.urandom(12)
        # keystream 由 sha256(key) 重复扩展而成
        ks = hashlib.sha256(key).digest() * ((length + 32) // 32 + 1)
        cipher = bytes(a ^ b for a, b in zip(plaintext, ks[:length]))
        header = OLD_VERSION + struct.pack("!I", length)
        payload = header + iv + cipher
        sig = hmac.new(key, payload, hashlib.sha256).digest()
        return payload + sig

    def _old_decrypt(self, full: bytes, key: bytes) -> bytes:
        # 验证 mac
        if len(full) < 6 + 32:
            raise ValueError("旧格式数据太短")
        sig, payload = full[-32:], full[:-32]
        expected = hmac.new(key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("旧格式校验失败：数据可能被篡改或密码错误")
        ver2, length = struct.unpack("!2sI", payload[:6])
        iv = payload[6:18]
        cipher = payload[18:18+length]
        ks = hashlib.sha256(key).digest() * ((length + 32) // 32 + 1)
        raw = bytes(a ^ b for a, b in zip(cipher, ks[:length]))
        return raw

    # --- new AES-GCM implementation helpers ---
    def _aesgcm_encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        # 返回 payload = NEW_VERSION || nonce(12) || ciphertext_and_tag
        if _have_cryptography:
            aes = AESGCM(key)
            nonce = os.urandom(12)
            ct = aes.encrypt(nonce, plaintext, NEW_VERSION)
            return NEW_VERSION + nonce + ct
        elif _have_pycrypto:
            nonce = os.urandom(12)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(NEW_VERSION)
            ct, tag = cipher.encrypt_and_digest(plaintext)
            return NEW_VERSION + nonce + ct + tag
        else:
            raise RuntimeError("No AEAD backend available")

    def _aesgcm_decrypt(self, payload: bytes, key: bytes) -> bytes:
        if len(payload) < 14:
            raise ValueError("新格式数据太短")
        nonce = payload[2:14]
        ct = payload[14:]
        if _have_cryptography:
            aes = AESGCM(key)
            raw = aes.decrypt(nonce, ct, NEW_VERSION)
            return raw
        elif _have_pycrypto:
            # ct = ciphertext || tag
            if len(ct) < 16:
                raise ValueError("新格式密文太短")
            cipher_text = ct[:-16]
            tag = ct[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            cipher.update(NEW_VERSION)
            raw = cipher.decrypt_and_verify(cipher_text, tag)
            return raw
        else:
            raise RuntimeError("No AEAD backend available")

    # --- public API ---
    def write(self, state: dict, pwd: str, allow_fallback: bool = True) -> str:
        """写入：优先使用 AEAD（AES-GCM）。如果没有 AEAD 后端且 allow_fallback=True，会使用旧实现写入（不安全）。
        返回 link_id（文件名基础）。
        """
        link_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
        salt = os.urandom(16)
        key = self._derive_key(pwd, salt)
        raw = json.dumps(state, ensure_ascii=False).encode("utf-8")

        path = os.path.join(self.store_dir, f"{link_id}.json")

        if _AESGCM is not None:
            try:
                payload = self._aesgcm_encrypt(raw, key)
            except Exception as e:
                # 如果 AEAD 报错，选择是否回退
                if not allow_fallback:
                    raise
                warnings.warn(f"AEAD 加密失败，回退到旧实现: {e}")
                payload = self._old_encrypt(raw, key)
        else:
            if allow_fallback:
                warnings.warn("没有可用的 AEAD 后端，使用旧不安全实现写入（允许回退模式）。")
                payload = self._old_encrypt(raw, key)
            else:
                raise RuntimeError("没有可用的 AEAD 后端，写入被拒绝（保护模式）。")

        final = base64.b64encode(payload).decode("ascii")
        store = {"id": link_id,
                 "salt": base64.b64encode(salt).decode("ascii"),
                 "ts": time.time(),
                 "data": final}
        atomic_write_json(path, store)
        return link_id

    def read(self, link_id: str, pwd: str, migrate_on_read: bool = False, allow_fallback: bool = True) -> dict:
        """读取：支持旧/新格式。若 migrate_on_read=True，则成功读取旧格式后会尝试写入新格式（生成新的 id）。
        allow_fallback 决定在没有 AEAD 时是否允许旧解码/写入行为。
        """
        path = os.path.join(self.store_dir, f"{link_id}.json")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Link {link_id} 不存在")
        with open(path, "r", encoding="utf-8") as f:
            store = json.load(f)

        salt = base64.b64decode(store["salt"])
        key = self._derive_key(pwd, salt)
        full = base64.b64decode(store["data"])

        if len(full) < 2:
            raise ValueError("数据太短")
        ver = full[:2]

        if ver == OLD_VERSION:
            # 旧格式解码
            try:
                raw = self._old_decrypt(full, key)
            except Exception as e:
                raise
            state = json.loads(raw.decode("utf-8"))
            if migrate_on_read:
                # 只在可用 AEAD 时尝试迁移；若不可用且允许回退，则不报错
                if _AESGCM is not None:
                    try:
                        self.write(state, pwd, allow_fallback=allow_fallback)
                    except Exception:
                        # 迁移失败不要中断读取
                        pass
                else:
                    warnings.warn("尝试迁移旧格式，但没有可用 AEAD 后端；保留旧文件。")
            return state

        elif ver == NEW_VERSION:
            try:
                raw = self._aesgcm_decrypt(full, key)
            except Exception as e:
                # 如果新格式解密失败且允许回退，尝试旧解码以防格式混淆
                if allow_fallback:
                    try:
                        raw = self._old_decrypt(full, key)
                        state = json.loads(raw.decode("utf-8"))
                        return state
                    except Exception:
                        pass
                raise
            state = json.loads(raw.decode("utf-8"))
            return state
        else:
            raise ValueError(f"未知 payload 版本: {ver.hex()}")
