"""加密打包的命名空间包构建期闸（缺 __init__.py → fail-fast）。"""
import pytest

from pkapp.packager.encrypt import _check_no_namespace_packages
from pkapp.packager.errors import BuildError


def _touch(root, rel):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("", encoding="utf-8")


def test_namespace_packages_check_ok(tmp_path):
    app = tmp_path / "app"
    for rel in ("__init__.py", "pkg/__init__.py", "pkg/mod.py"):
        _touch(app, rel)
    _check_no_namespace_packages(str(app))


def test_namespace_packages_check_rejects_missing(tmp_path):
    app = tmp_path / "app"
    for rel in ("__init__.py", "pkg/mod.py"):
        _touch(app, rel)
    with pytest.raises(BuildError, match="pkg"):
        _check_no_namespace_packages(str(app))


def test_namespace_packages_check_rejects_intermediate_missing(tmp_path):
    app = tmp_path / "app"
    for rel in ("__init__.py", "parent/child/__init__.py",
                "parent/child/mod.py"):
        _touch(app, rel)
    with pytest.raises(BuildError) as ei:
        _check_no_namespace_packages(str(app))
    assert "parent" in str(ei.value)
    assert "parent/child" not in str(ei.value)   # 只报真正缺的那一层
