"""icons.py 生成器单元测试：尺寸矩阵 / 安全区布局 / 背景取色 / 源图校验。"""
import os

import pytest
from PIL import Image

from pkapp.packager.icons import IconError, generate_android_icons

_BUCKETS = {"mdpi": (48, 108), "hdpi": (72, 162), "xhdpi": (96, 216),
            "xxhdpi": (144, 324), "xxxhdpi": (192, 432)}


def _source(tmp_path, size=(432, 432), color=(180, 40, 40), mode="RGB"):
    png = os.path.join(str(tmp_path), "src.png")
    Image.new(mode, size, color).save(png)
    return png


def test_generate_full_set(tmp_path):
    """全密度传统位图 + 前景层尺寸矩阵；anydpi-v26 定义 + 背景均色。"""
    out = os.path.join(str(tmp_path), "res")
    assert generate_android_icons(_source(tmp_path), out) == out
    for bucket, (legacy, canvas) in _BUCKETS.items():
        d = os.path.join(out, f"mipmap-{bucket}")
        assert Image.open(os.path.join(d, "ic_app.png")).size == (legacy, legacy)
        fg_path = os.path.join(d, "ic_app_foreground.png")
        assert Image.open(fg_path).size == (canvas, canvas)
    xml = open(os.path.join(out, "mipmap-anydpi-v26", "ic_app.xml"),
               encoding="utf-8").read()
    assert 'android:drawable="@color/ic_app_background"' in xml
    assert 'android:drawable="@mipmap/ic_app_foreground"' in xml
    values = open(os.path.join(out, "values", "ic_app.xml"), encoding="utf-8").read()
    assert "<color name=\"ic_app_background\">#B42828</color>" in values


def test_foreground_safe_zone(tmp_path):
    """前景层内容缩进 66/108 安全区：中心不透明、外圈透明（432 画布 → 264 内容区）。"""
    out = os.path.join(str(tmp_path), "res")
    generate_android_icons(_source(tmp_path), out)
    fg = Image.open(os.path.join(out, "mipmap-xxxhdpi", "ic_app_foreground.png"))
    assert fg.getpixel((216, 216))[:3] == (180, 40, 40)   # 中心 = 源图色
    assert fg.getpixel((10, 10))[3] == 0                  # 安全区外透明
    offset = (432 - 264) // 2
    assert fg.getpixel((offset - 2, offset - 2))[3] == 0  # 内容区外沿仍透明


def test_non_square_center_crop(tmp_path):
    """非方形源图 → 中心裁方后正常产出（500×432 裁掉两侧各 34px）。"""
    out = os.path.join(str(tmp_path), "res")
    generate_android_icons(_source(tmp_path, size=(500, 432)), out)
    assert Image.open(os.path.join(out, "mipmap-mdpi", "ic_app.png")).size == (48, 48)


def test_source_too_small(tmp_path):
    """源图 < 432×432 → 拒绝（xxxhdpi 前景层需原生分辨率）。"""
    with pytest.raises(IconError, match="至少 432"):
        generate_android_icons(_source(tmp_path, size=(192, 192)),
                               os.path.join(str(tmp_path), "res"))


def test_transparent_edge_falls_back_white(tmp_path):
    """边缘全透明源图 → 背景层回退白（#FFFFFF）。"""
    img = Image.new("RGBA", (432, 432), (0, 0, 0, 0))
    for x in range(100, 332):        # 中心区实心，四周透明
        for y in range(100, 332):
            img.putpixel((x, y), (10, 20, 30, 255))
    png = os.path.join(str(tmp_path), "src.png")
    img.save(png)
    out = os.path.join(str(tmp_path), "res")
    generate_android_icons(png, out)
    values = open(os.path.join(out, "values", "ic_app.xml"), encoding="utf-8").read()
    assert "#FFFFFF" in values


def test_source_missing(tmp_path):
    """源图文件不存在 → IconError（与格式错误分开报）。"""
    with pytest.raises(IconError, match="图标文件不存在"):
        generate_android_icons(os.path.join(str(tmp_path), "nope.png"),
                               os.path.join(str(tmp_path), "res"))


def test_unreadable_source(tmp_path):
    """非位图内容 → IconError。"""
    bad = os.path.join(str(tmp_path), "bad.png")
    with open(bad, "wb") as f:
        f.write(b"not an image")
    with pytest.raises(IconError, match="图标无法识别"):
        generate_android_icons(bad, os.path.join(str(tmp_path), "res"))
