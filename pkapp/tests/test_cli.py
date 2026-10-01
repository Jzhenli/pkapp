"""CLI 五命令接线冒烟（argparse → cmd_* 分发）。"""
from pkapp.cli import main


def test_create_and_check(tmp_path):
    proj = str(tmp_path / "proj")
    assert main(["create", "proj", "--dir", proj, "--no-venv"]) == 0
    assert main(["check", "--project", proj]) == 0


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
