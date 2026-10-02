"""Android 启动器图标组生成器（Briefcase 同式：单源 PNG → 全密度 mipmap + 自适应图标）。

规范（developer.android.com「自适应图标」/ briefcase icon-format）：
- 自适应图标图层画布 = 108dp 网格，内容须落在 66dp 安全区内（外圈 18dp 预留蒙版/
  视差效果，永不裁切）；图层密度：mdpi 108 / hdpi 162 / xhdpi 216 / xxhdpi 324 /
  xxxhdpi 432。
- 传统位图（minSdk 24 → API 24/25 启动器仍读位图）：mdpi 48 / hdpi 72 / xhdpi 96 /
  xxhdpi 144 / xxxhdpi 192。
- 单源图无法拆双图层 → foreground = 源图缩放进 66/108 安全区居中（透明垫底）；
  background = 源图不透明边缘均色（边缘全透明回退白）。

产出目录树（pkapp 暂存后经 -PpkappIconRes 挂 gradle variant sourceSet，manifest
android:icon 经 ${pkappIcon} placeholder 切到 @mipmap/ic_app）：
  mipmap-{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}/ic_app.png           # 传统位图
  mipmap-{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}/ic_app_foreground.png # 自适应前景层
  mipmap-anydpi-v26/ic_app.xml                                  # 自适应图标定义
  values/ic_app.xml                                             # 背景层纯色
"""
from __future__ import annotations

import os

# (密度桶, 倍率)：mdpi = 1dp×1px 基准
_DENSITIES = (("mdpi", 1.0), ("hdpi", 1.5), ("xhdpi", 2.0),
              ("xxhdpi", 3.0), ("xxxhdpi", 4.0))
_LEGACY_DP = 48     # 传统位图边长（dp）
_ADAPTIVE_DP = 108  # 自适应图层画布边长（dp）
_SAFE_DP = 66       # 安全区边长（dp）——内容最大外接，防 OEM 蒙版裁切
_MIN_SOURCE = 432   # 源图最小边长（= xxxhdpi 前景画布，避免放大模糊）


class IconError(ValueError):
    """图标源不可用（无法识别 / 过小）。"""


def generate_android_icons(source: str, out_dir: str) -> str:
    """单源 PNG → out_dir 下图标组；返回 out_dir；源不可用抛 IconError。

    非方形源图取中心裁方（Briefcase 同语义）；缩放用 LANCZOS。
    """
    try:
        from PIL import Image
    except ImportError as e:
        raise IconError(f"pillow 未安装（pkapp 依赖应自带）: {e}") from None

    if not os.path.isfile(source):
        raise IconError(f"图标文件不存在: {source}")
    try:
        img = Image.open(source).convert("RGBA")
    except Exception as e:
        raise IconError(f"图标无法识别（须 PNG 等位图格式）: {source} ({e})") from None
    side = min(img.size)
    if img.size != (side, side):
        left = (img.width - side) // 2
        top = (img.height - side) // 2
        img = img.crop((left, top, left + side, top + side))
    if side < _MIN_SOURCE:
        raise IconError(
            f"图标源过小: {img.width}×{img.height}，至少 {_MIN_SOURCE}×{_MIN_SOURCE}"
            f"（xxxhdpi 自适应前景层需原生分辨率，建议 1024×1024）: {source}")

    bg = _edge_color(img)
    for bucket, mult in _DENSITIES:
        d = os.path.join(out_dir, f"mipmap-{bucket}")
        os.makedirs(d, exist_ok=True)
        img.resize((round(_LEGACY_DP * mult),) * 2,
                   Image.Resampling.LANCZOS).save(os.path.join(d, "ic_app.png"))
        canvas = round(_ADAPTIVE_DP * mult)
        inner = round(_SAFE_DP / _ADAPTIVE_DP * canvas)
        fg = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
        offset = (canvas - inner) // 2
        fg.paste(img.resize((inner, inner), Image.Resampling.LANCZOS),
                 (offset, offset))
        fg.save(os.path.join(d, "ic_app_foreground.png"))

    _write(os.path.join(out_dir, "mipmap-anydpi-v26", "ic_app.xml"),
           '<?xml version="1.0" encoding="utf-8"?>\n'
           '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
           '    <background android:drawable="@color/ic_app_background"/>\n'
           '    <foreground android:drawable="@mipmap/ic_app_foreground"/>\n'
           '</adaptive-icon>\n')
    _write(os.path.join(out_dir, "values", "ic_app.xml"),
           '<?xml version="1.0" encoding="utf-8"?>\n'
           '<resources>\n'
           f'    <color name="ic_app_background">{bg}</color>\n'
           '</resources>\n')
    os.utime(out_dir, None)   # 防增量资源合并的 mtime 盲区（同 assets 触坑）
    return out_dir


def _edge_color(img) -> str:
    """源图不透明边缘均色（#RRGGBB）；边缘全透明回退白——自适应背景层取色。

    原始分辨率逐像素采最外圈（透明像素 RGB 常为黑，缩放采样会混入失真）。
    """
    w, h = img.size
    px = img.load()
    rs = gs = bs = n = 0
    for x in range(w):                      # 上下两条边（含四角）
        for y in (0, h - 1):
            r, g, b, a = px[x, y]
            if a >= 128:
                rs += r; gs += g; bs += b; n += 1
    for y in range(1, h - 1):               # 左右两边（四角已计）
        for x in (0, w - 1):
            r, g, b, a = px[x, y]
            if a >= 128:
                rs += r; gs += g; bs += b; n += 1
    if n == 0:
        return "#FFFFFF"
    return f"#{rs // n:02X}{gs // n:02X}{bs // n:02X}"


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
