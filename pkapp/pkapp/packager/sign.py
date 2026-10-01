"""Ed25519 签名（M0 D1 决策：minisign 的轻量替代——Ed25519 私钥签 manifest 规范化字节）。

格式：manifest.signature = base64(64 字节 Ed25519 签名)。
被签内容 = manifest 文本去掉 signature 行后的原始字节（§2 验签顺序：先验签再校验其余键）。
公钥以 32 字节 raw hex 输出（壳内置；壳侧用任意 Ed25519 C 实现可验）。
私钥位置：PKAPP_SIGN_KEY 环境变量 > 项目 .pkapp/sign.key > 构建失败（--unsigned 旁路仅供 dev/test）。
"""
from __future__ import annotations

import base64
import os
from pathlib import Path


class SignError(ValueError):
    """签名材料缺失 / 验签失败。"""


def generate_keypair(out_dir: str, name: str = "sign") -> tuple[str, str]:
    """生成 Ed25519 密钥对：私钥 PEM 存 <out_dir>/<name>.key，返回 (私钥路径, 公钥 hex)。"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    pub_hex = key.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw).hex()
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = os.path.join(out_dir, f"{name}.key")
    Path(path).write_bytes(pem)
    return path, pub_hex


def _load_private(path: str):
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def resolve_private_key(explicit: str | None, project_dir: str) -> str | None:
    """私钥发现顺序：--key / PKAPP_SIGN_KEY / <project>/.pkapp/sign.key。找不到返回 None。"""
    if explicit:
        if not os.path.isfile(explicit):
            raise SignError(f"--key 指定的私钥不存在: {explicit}")
        return explicit
    env = os.environ.get("PKAPP_SIGN_KEY")
    if env:
        if not os.path.isfile(env):
            raise SignError(f"PKAPP_SIGN_KEY 指向的私钥不存在: {env}")
        return env
    default = os.path.join(project_dir, ".pkapp", "sign.key")
    return default if os.path.isfile(default) else None


def sign_bytes(private_path: str, data: bytes) -> str:
    """返回 base64 签名（供 manifest.signature）。"""
    from cryptography.exceptions import InvalidKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    try:
        key = _load_private(private_path)
    except (ValueError, InvalidKey) as e:
        raise SignError(f"私钥解析失败 {private_path}: {e}") from e
    if not isinstance(key, Ed25519PrivateKey):  # rust 绑定无 .curve 属性，只能 isinstance
        raise SignError(f"私钥不是 Ed25519: {private_path}")
    return base64.b64encode(key.sign(data)).decode("ascii")


def public_key_hex(private_path: str) -> str:
    from cryptography.hazmat.primitives import serialization

    key = _load_private(private_path)
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def verify(public_hex: str, data: bytes, signature_b64: str) -> bool:
    """壳侧同款验签逻辑（工具层用于 G4 负向测试与 verify_spk）。"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
        pub.verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False
