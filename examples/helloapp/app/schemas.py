"""Pydantic 请求模型（入参校验；出参 dict 直出，保持示例轻量）。

extra="forbid"：多余字段直接 422——防手滑写错字段名被静默丢弃。
PATCH 语义：模型字段全 Optional，端点用 exclude_unset 只改显式传入的字段。
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

DeviceStatus = Literal["online", "offline", "error"]


class DeviceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sn: str = Field(min_length=1, max_length=64, description="序列号（唯一键）")
    name: str = Field(min_length=1, max_length=64)
    model: str = Field("", max_length=64, description="设备型号")
    group_id: int | None = Field(None, description="所属分组；null = 未分组")
    status: DeviceStatus = "offline"


class DeviceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, min_length=1, max_length=64)
    model: str | None = Field(None, max_length=64)
    group_id: int | None = Field(None, description="None = 不修改（移组传目标分组 id）")
    status: DeviceStatus | None = None


class GroupCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    description: str = Field("", max_length=256)


class GroupUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, min_length=1, max_length=64)
    description: str | None = Field(None, max_length=256)


class PasswordChange(BaseModel):
    old_password: str = Field(min_length=1)
    new_password: str = Field(min_length=6, max_length=64)


class PasswordReset(BaseModel):
    new_password: str = Field(min_length=6, max_length=64)


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=2, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=6, max_length=64)
    roles: list[str] = Field(default_factory=lambda: ["viewer"])
