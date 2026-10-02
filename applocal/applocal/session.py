"""applocal.session —— lan 模式会话层（机制）：密码哈希/用户表/会话/限速。

方案：docs/NETWORK_AUTH_DESIGN.md ★v1.1 定稿★ §5–§7。
零依赖（纯 stdlib）；rbac/ 消费本层产出的 Identity，但本层不 import rbac（§4 解耦）。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time

PBKDF2_ITER = 100_000                       # ★v1.1 裁定★：PBKDF2-HMAC-SHA256，零依赖
DEFAULT_SESSION_TTL_S = 7 * 24 * 3600       # §6：滑动 7 天（MYAPP_SESSION_DAYS 可调）
LOCK_THRESHOLD, LOCK_SECONDS = 5, 60        # §6：失败 5 次锁 60s（per-IP，内存态）
COOKIE_NAME = "sid"
SESSION_SAVE_MIN_S = 60                     # 滑动续期落盘节流：重启丢失窗口 ≤60s，避免每请求写盘


# ── 密码（PBKDF2-HMAC-SHA256）───────────────────────────────────────────
def hash_password(password: str, *, _iter: int = PBKDF2_ITER) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _iter)
    return f"pbkdf2${_iter}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


# ── 用户表（data_dir/users.json；原子写）───────────────────────────────
_EQ_HASH: list[str] = []       # 惰性假 hash：抹平"用户不存在"与"密码错误"的 PBKDF2 耗时差


def _eq_hash() -> str:
    """防用户名枚举：缺失用户也跑一次等价 PBKDF2（首查贵一次，之后复用）。"""
    if not _EQ_HASH:
        _EQ_HASH.append(hash_password("timing-equalizer"))
    return _EQ_HASH[0]


class UserStore:
    def __init__(self, data_dir: str) -> None:
        self.path = os.path.join(data_dir, "users.json")
        self._users: dict = {}
        self._mtime: float = 0.0
        self._load()

    def _load(self) -> None:
        """全量载入；损坏视为无用户 → 走首装（§8.2）。"""
        try:
            self._mtime = os.stat(self.path).st_mtime
        except OSError:
            self._mtime = 0.0
        self._users = {}
        if os.path.isfile(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    self._users = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._users = {}

    def _reload_if_changed(self) -> None:
        """mtime 变更检测（方案A）：应用后端运行中建/改/删用户，门免重启可见。

        门与应用各持 UserStore 实例（同 data_dir）：应用写自己的表并原子落盘，
        门在 verify/exists 前 stat 一次，变了就重读——权威数据回到文件。
        """
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            mtime = 0.0                          # 文件被删 → 视为变更（重启后重种子）
        if mtime != self._mtime:
            self._load()

    def exists(self) -> bool:
        self._reload_if_changed()
        return bool(self._users)

    def all(self) -> dict:
        self._reload_if_changed()
        return dict(self._users)

    def verify(self, user: str, password: str) -> dict | None:
        self._reload_if_changed()
        rec = self._users.get(user)
        if not isinstance(rec, dict):
            verify_password(password, _eq_hash())   # 恒定耗时：用户存在性不外泄（F3 修复）
            return None
        return rec if verify_password(password, rec.get("pw_hash", "")) else None

    def create(self, user: str, password: str, roles: list[str]) -> None:
        if not user or user in self._users:
            raise ValueError(f"user invalid or exists: {user!r}")
        self._users[user] = {"pw_hash": hash_password(password), "roles": list(roles),
                             "created": time.strftime("%Y-%m-%d %H:%M")}
        self.save()

    def remove(self, user: str) -> bool:
        if user not in self._users:
            return False
        del self._users[user]
        self.save()
        return True

    def set_password(self, user: str, password: str) -> bool:
        if user not in self._users:
            return False
        self._users[user]["pw_hash"] = hash_password(password)
        self._users[user]["updated"] = time.strftime("%Y-%m-%d %H:%M")
        self.save()
        return True

    def save(self) -> None:
        tmp = f"{self.path}.tmp{os.getpid()}"   # pid 后缀：门与应用双实例并发写不碰撞
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._users, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)              # 原子写（tmp+rename，项目铁律）


# ── 会话（data_dir/sessions.json；滑动过期；原子写）────────────────────
class SessionStore:
    def __init__(self, data_dir: str, ttl_s: int = DEFAULT_SESSION_TTL_S) -> None:
        self.path = os.path.join(data_dir, "sessions.json")
        self.ttl_s = ttl_s
        self._sessions: dict[str, dict] = {}
        if os.path.isfile(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    self._sessions = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._sessions = {}             # 解析失败按未登录处理（项目铁律）

    def create(self, user: str, roles: list[str], perms: list[str]) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = {"user": user, "roles": list(roles),
                                 "perms": list(perms), "renewed": time.time(),
                                 "expires": time.time() + self.ttl_s}
        self.save()
        return token

    def resolve(self, token: str | None) -> dict | None:
        """返回 identity dict（user/roles/perms）或 None；命中即滑动续期。

        续期落盘节流（SESSION_SAVE_MIN_S）：每请求原子写 sessions.json 不可承受；
        重启最多回退 60s 的续期量，"滑动 7 天"语义仍成立。
        """
        if not token:
            return None
        s = self._sessions.get(token)
        if not isinstance(s, dict):
            return None
        now = time.time()
        if s.get("expires", 0) < now:
            del self._sessions[token]
            self.save()
            return None
        s["expires"] = now + self.ttl_s
        if now - s.get("renewed", 0.0) >= SESSION_SAVE_MIN_S:
            s["renewed"] = now
            self.save()
        return {"user": s["user"], "roles": s["roles"], "perms": s["perms"]}

    def drop(self, token: str | None) -> None:
        if token and token in self._sessions:
            del self._sessions[token]
            self.save()

    def drop_all(self) -> None:                 # 全局登出 = 清表
        self._sessions.clear()
        self.save()

    def save(self) -> None:
        tmp = f"{self.path}.tmp{os.getpid()}"   # pid 后缀：并发写不碰撞（同 UserStore）
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._sessions, f)
        os.replace(tmp, self.path)


# ── 登录限速（内存 per-IP；进程重启即清零）─────────────────────────────
class RateLimiter:
    def __init__(self, threshold: int = LOCK_THRESHOLD, seconds: int = LOCK_SECONDS) -> None:
        self._fails: dict[str, list] = {}
        self._threshold, self._seconds = threshold, seconds

    def locked(self, ip: str) -> bool:
        rec = self._fails.get(ip)
        return bool(rec and rec[1] > time.time())

    def fail(self, ip: str) -> None:
        rec = self._fails.setdefault(ip, [0, 0.0])
        rec[0] += 1
        if rec[0] >= self._threshold:
            rec[1] = time.time() + self._seconds
            rec[0] = 0

    def reset(self, ip: str) -> None:
        self._fails.pop(ip, None)


def cookie_header(token: str, ttl_s: int = DEFAULT_SESSION_TTL_S) -> str:
    """Set-Cookie 值：HttpOnly + SameSite=Strict（§6 CSRF 防线）。"""
    return (f"{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/; "
            f"Max-Age={ttl_s}")


def cookie_clear_header() -> str:
    return f"{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"


def cookie_token(scope) -> str | None:
    """从 ASGI scope headers 解析 sid Cookie。"""
    for k, v in scope.get("headers", []):
        if k == b"cookie":
            for part in v.decode("utf-8", "replace").split(";"):
                name, _, val = part.strip().partition("=")
                if name == COOKIE_NAME:
                    return val or None
    return None
