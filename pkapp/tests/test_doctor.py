"""doctor 命令：诊断信息输出与退出码（无 venv/无快照 → 1）。"""
from pkapp.commands.create import cmd_create
from pkapp.commands.doctor import cmd_doctor


def test_doctor_reports_problems(tmp_path, capsys):
    root = str(tmp_path / "demo")
    assert cmd_create("demo", root, no_venv=True) == 0
    assert cmd_doctor(root) == 1            # applocal 缺失（无 .venv）+ runtime 未注册
    out = capsys.readouterr().out
    assert "[doctor]" in out and "WebView2" in out
