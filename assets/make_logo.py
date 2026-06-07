"""Generate the XSEC logo as PNGs.

Draws a rounded-square app icon: a deep indigo->cyan gradient, a security
shield, and a bold 'X' crosshair mark. Rendered at 4x then downscaled for
clean antialiasing. Run: python3 assets/make_logo.py
"""

from __future__ import annotations

import os

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
SCALE = 8          # supersample factor
SIZE = 128         # final icon size


def _lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _gradient(size, top, bottom):
    img = Image.new("RGB", (size, size))
    px = img.load()
    for y in range(size):
        t = y / (size - 1)
        row = _lerp(top, bottom, t)
        for x in range(size):
            px[x, y] = row
    return img


def _rounded_mask(size, radius):
    mask = Image.new("L", (size, size), 0)
    d = ImageDraw.Draw(mask)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return mask


def build(size=SIZE) -> Image.Image:
    S = size * SCALE
    # background: indigo -> cyan diagonal-ish (vertical is fine at this size)
    bg = _gradient(S, (79, 70, 229), (6, 182, 212))     # #4f46e5 -> #06b6d4
    icon = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    icon.paste(bg, (0, 0))
    icon.putalpha(_rounded_mask(S, radius=int(S * 0.22)))

    # draw the emblem on its own layer so translucency composites correctly
    overlay = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    cx = S / 2
    top = S * 0.18
    bottom = S * 0.86
    half = S * 0.27
    shoulder = S * 0.33
    shield = [
        (cx, top),
        (cx + half, shoulder),
        (cx + half, S * 0.55),
        (cx, bottom),
        (cx - half, S * 0.55),
        (cx - half, shoulder),
    ]
    # solid white shield, so the dark X reads cleanly inside it
    draw.polygon(shield, fill=(255, 255, 255, 245))

    # bold 'X' crosshair in indigo, contrasting against the white shield
    mx, my = cx, S * 0.50
    arm = S * 0.15
    w = int(S * 0.058)
    ink = (49, 46, 129, 255)        # #312e81 indigo
    draw.line([(mx - arm, my - arm), (mx + arm, my + arm)], fill=ink, width=w)
    draw.line([(mx - arm, my + arm), (mx + arm, my - arm)], fill=ink, width=w)
    # cyan center dot, like a scanner lock
    r = S * 0.032
    draw.ellipse([mx - r, my - r, mx + r, my + r], fill=(6, 182, 212, 255))

    icon = Image.alpha_composite(icon, overlay)
    return icon.resize((size, size), Image.LANCZOS)


def main():
    icon = build(128)
    icon.save(os.path.join(HERE, "icon.png"))
    build(512).save(os.path.join(HERE, "logo-512.png"))
    # a wide banner for the README
    banner = Image.new("RGBA", (1280, 320), (15, 17, 21, 255))
    big = build(220)
    banner.alpha_composite(big, (60, 50))
    banner.convert("RGB").save(os.path.join(HERE, "banner.png"))
    print("wrote icon.png (128), logo-512.png, banner.png")


if __name__ == "__main__":
    main()
