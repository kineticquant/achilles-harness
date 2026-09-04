#!/usr/bin/env python3
"""Build window / taskbar / tray icons from the Cinzel Decorative lambda mark.

Source mark: achilles-lambda-white.png (Decorative A with the crossbar removed).
Regenerate that PNG with website/fonts/_extract_deco_lambda.py if the font changes.
"""

from __future__ import annotations

import struct
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent
MARK_SRC = ROOT / "achilles-lambda-white.png"

LIGHT_BG = (244, 244, 244, 255)
DARK_BG = (23, 23, 23, 255)
MARK_DARK = (16, 16, 16)
MARK_WHITE = (255, 255, 255)
UPDATE_DOT = (37, 99, 235, 255)


def crop_mark(im: Image.Image) -> Image.Image:
    im = im.convert("RGBA")
    bbox = im.getbbox()
    return im.crop(bbox) if bbox else im


def thicken(im: Image.Image, radius: int = 22) -> Image.Image:
    """Grow the glyph so thin Cinzel Decorative strokes survive 16–32px icons."""
    alpha = im.getchannel("A").filter(ImageFilter.MaxFilter(radius * 2 + 1))
    out = Image.new("RGBA", im.size, (255, 255, 255, 0))
    out.putalpha(alpha)
    return out


def recolor(im: Image.Image, rgb: tuple[int, int, int]) -> Image.Image:
    r, g, b = rgb
    out = im.copy()
    pixels = out.load()
    width, height = out.size
    for y in range(height):
        for x in range(width):
            _r, _g, _b, a = pixels[x, y]
            pixels[x, y] = (r, g, b, a)
    return out


def rounded_square(size: int, fill: tuple[int, int, int, int]) -> Image.Image:
    im = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(im).rounded_rectangle(
        (0, 0, size - 1, size - 1),
        radius=max(1, int(size * 0.195)),
        fill=fill,
    )
    return im


def fit_mark(mark: Image.Image, box: int, rgb: tuple[int, int, int]) -> Image.Image:
    fitted = recolor(mark, rgb)
    fitted.thumbnail((box, box), Image.Resampling.LANCZOS)
    return fitted


def compose_app(mark: Image.Image, size: int, *, dark: bool = False) -> Image.Image:
    canvas = rounded_square(size, DARK_BG if dark else LIGHT_BG)
    pad = max(1, int(size * (0.10 if size <= 32 else 0.14)))
    fg = MARK_WHITE if dark else MARK_DARK
    fitted = fit_mark(mark, size - 2 * pad, fg)
    x = (size - fitted.width) // 2
    y = (size - fitted.height) // 2
    canvas.alpha_composite(fitted, (x, y))
    return canvas


def compose_glyph(mark: Image.Image, size: int, rgb: tuple[int, int, int]) -> Image.Image:
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    pad = max(1, int(size * (0.04 if size <= 32 else 0.08)))
    fitted = fit_mark(mark, size - 2 * pad, rgb)
    x = (size - fitted.width) // 2
    y = (size - fitted.height) // 2
    canvas.alpha_composite(fitted, (x, y))
    return canvas


def with_update_dot(im: Image.Image) -> Image.Image:
    out = im.copy()
    draw = ImageDraw.Draw(out)
    size = out.size[0]
    r = max(2, int(size * 0.18))
    margin = max(1, int(size * 0.08))
    box = (size - 2 * r - margin, size - 2 * r - margin, size - margin, size - margin)
    draw.ellipse(box, fill=UPDATE_DOT)
    return out


def png_bytes(im: Image.Image) -> bytes:
    buf = BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def write_ico(path: Path, images: list[Image.Image]) -> None:
    pngs = [png_bytes(im) for im in images]
    offset = 6 + 16 * len(pngs)
    entries = bytearray()
    for im, data in zip(images, pngs):
        width, height = im.size
        entries += struct.pack(
            "<BBBBHHII",
            0 if width >= 256 else width,
            0 if height >= 256 else height,
            0,
            0,
            1,
            32,
            len(data),
            offset,
        )
        offset += len(data)
    path.write_bytes(struct.pack("<HHH", 0, 1, len(pngs)) + entries + b"".join(pngs))


def write_icns(path: Path, sized: dict[int, Image.Image]) -> None:
    mapping = {
        16: [b"icp4"],
        32: [b"icp5", b"ic11"],
        64: [b"icp6", b"ic12"],
        128: [b"ic07"],
        256: [b"ic08", b"ic13"],
        512: [b"ic09", b"ic14"],
        1024: [b"ic10"],
    }
    blocks = []
    for size, ostypes in mapping.items():
        data = png_bytes(sized[size])
        for ostype in ostypes:
            blocks.append(ostype + struct.pack(">I", 8 + len(data)) + data)
    body = b"".join(blocks)
    path.write_bytes(b"icns" + struct.pack(">I", 8 + len(body)) + body)


def write_svg(path: Path, preview: Image.Image) -> None:
    preview = preview.resize((256, 256), Image.Resampling.LANCZOS)
    b64 = __import__("base64").b64encode(png_bytes(preview)).decode("ascii")
    path.write_text(
        f"""<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg width="2048" height="2048" viewBox="0 0 2048 2048" xmlns="http://www.w3.org/2000/svg">
  <image href="data:image/png;base64,{b64}" x="0" y="0" width="2048" height="2048"/>
</svg>
""",
        encoding="utf-8",
    )


def write_glyph_svg(path: Path, mark: Image.Image) -> None:
    glyph = compose_glyph(mark, 256, MARK_DARK)
    b64 = __import__("base64").b64encode(png_bytes(glyph)).decode("ascii")
    path.write_text(
        f"""<svg width="600" height="600" viewBox="0 0 600 600" fill="none" xmlns="http://www.w3.org/2000/svg">
  <image href="data:image/png;base64,{b64}" x="0" y="0" width="600" height="600"/>
</svg>
""",
        encoding="utf-8",
    )


def main() -> None:
    mark = thicken(crop_mark(Image.open(MARK_SRC)))

    light = {size: compose_app(mark, size, dark=False) for size in (16, 24, 32, 48, 64, 128, 256, 512, 1024, 2048)}
    dark = {size: compose_app(mark, size, dark=True) for size in (16, 32, 128, 256, 512, 1024)}

    light[1024].save(ROOT / "icon.png")
    light[2048].save(ROOT / "icon@2x.png")
    light[512].save(ROOT / "icon-512.png")
    dark[1024].save(ROOT / "icon-light.png")

    ico_sizes = (16, 24, 32, 48, 64, 128, 256)
    # Dark tile (white mark): used for the exe, installer, and
    # Programs and Features entry on Windows.
    write_ico(
        ROOT / "icon.ico",
        [dark[s] if s in dark else compose_app(mark, s, dark=True) for s in ico_sizes],
    )

    write_icns(ROOT / "icon.icns", {s: light[s] for s in (16, 32, 64, 128, 256, 512, 1024)})
    light_icns = {s: dark[s] if s in dark else compose_app(mark, s, dark=True) for s in (16, 32, 64, 128, 256, 512, 1024)}
    tmp = ROOT / "icon-light.icns.tmp"
    write_icns(tmp, light_icns)
    dest = ROOT / "icon-light.icns"
    dest.unlink(missing_ok=True)
    tmp.replace(dest)

    compose_glyph(mark, 22, MARK_DARK).save(ROOT / "iconTemplate.png")
    compose_glyph(mark, 44, MARK_DARK).save(ROOT / "iconTemplate@2x.png")
    with_update_dot(compose_glyph(mark, 22, MARK_DARK)).save(ROOT / "iconTemplateUpdate.png")
    with_update_dot(compose_glyph(mark, 44, MARK_DARK)).save(ROOT / "iconTemplateUpdate@2x.png")

    compose_glyph(mark, 32, MARK_WHITE).save(ROOT / "iconTray-win.png")
    compose_glyph(mark, 64, MARK_WHITE).save(ROOT / "iconTray-win@2x.png")
    with_update_dot(compose_glyph(mark, 32, MARK_WHITE)).save(ROOT / "iconTrayUpdate-win.png")

    write_svg(ROOT / "icon.svg", light[1024])
    write_glyph_svg(ROOT / "glyph.svg", mark)
    print("Wrote Achilles lambda icons in", ROOT)


if __name__ == "__main__":
    main()
