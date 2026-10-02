"""CLI 七命令接线冒烟（argparse → cmd_* 分发）。"""
from pkapp.cli import main


def test_create_and_check(tmp_path):
    proj = str(tmp_path / "proj")
    assert main(["create", "proj", "--dir", proj, "--no-venv"]) == 0
    assert main(["check", "--project", proj]) == 0


def test_fetch_list(capsys):
    """fetch --list：pin 清单输出（零联网）。"""
    assert main(["fetch", "windows", "--list"]) == 0
    out = capsys.readouterr().out
    assert "pbs-cpython-3.12.14" in out
    assert main(["fetch", "android", "--list"]) == 0
    out = capsys.readouterr().out
    assert "jdk17" in out and "py-android-3.12.14-arm64-v8a" in out


def test_dev_usage_error(tmp_path):
    proj = str(tmp_path / "p2")
    main(["create", "p2", "--dir", proj, "--no-venv"])
    assert main(["dev", "--project", proj]) == 2   # 无 .venv → 用法错误


def test_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit as e:
        assert e.code == 0
    assert "pkapp" in capsys.readouterr().out
