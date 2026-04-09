#!/usr/bin/env python3
"""
generate_icons.py
Generates the required PWA icons (192x192, 512x512) and a placeholder
screenshot (1280x720) into the icons/ folder.

Run once before building the Docker image:
    pip install Pillow cairosvg
    python generate_icons.py

If cairosvg is unavailable, the script falls back to a simple
programmatic PNG using Pillow only.
"""
from pathlib import Path

OUT = Path("icons")
OUT.mkdir(exist_ok=True)

SVG = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <rect width="100" height="100" rx="20" fill="#13161b"/>
  <rect x="10" y="10" width="35" height="35" rx="5" fill="none" stroke="#22d3a5" stroke-width="5"/>
  <rect x="55" y="10" width="35" height="35" rx="5" fill="none" stroke="#22d3a5" stroke-width="5"/>
  <rect x="10" y="55" width="35" height="35" rx="5" fill="none" stroke="#22d3a5" stroke-width="5"/>
  <rect x="55" y="55" width="35" height="35" rx="5" fill="none" stroke="#22d3a5" stroke-width="5"/>
</svg>
"""

def make_icons_pillow():
    from PIL import Image, ImageDraw

    for size in (192, 512):
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        r = size // 5  # corner radius
        # Background rounded rect
        d.rounded_rectangle([0, 0, size-1, size-1], radius=size//8, fill=(19, 22, 27, 255))
        # Four grid squares
        pad  = int(size * 0.10)
        gap  = int(size * 0.08)
        half = (size - 2*pad - gap) // 2
        sw   = max(2, size // 48)
        teal = (34, 211, 165, 255)
        positions = [
            (pad, pad),
            (pad + half + gap, pad),
            (pad, pad + half + gap),
            (pad + half + gap, pad + half + gap),
        ]
        for (x, y) in positions:
            d.rounded_rectangle([x, y, x+half, y+half], radius=max(2, size//32),
                                 outline=teal, width=sw)
        img.save(OUT / f"icon-{size}.png")
        print(f"  icons/icon-{size}.png  ✓")

    # Screenshot placeholder
    ss = Image.new("RGB", (1280, 720), (11, 13, 16))
    ss.save(OUT / "screenshot.png")
    print("  icons/screenshot.png  ✓")

try:
    import cairosvg
    for size in (192, 512):
        cairosvg.svg2png(bytestring=SVG.encode(), write_to=str(OUT/f"icon-{size}.png"),
                         output_width=size, output_height=size)
        print(f"  icons/icon-{size}.png  ✓  (cairosvg)")
    from PIL import Image
    ss = Image.new("RGB", (1280, 720), (11, 13, 16))
    ss.save(OUT / "screenshot.png")
    print("  icons/screenshot.png  ✓")
except ImportError:
    print("cairosvg not found — falling back to Pillow renderer")
    try:
        make_icons_pillow()
    except ImportError:
        print("Pillow not found either. Install it:  pip install Pillow")
        raise

print("\nDone. Copy the icons/ folder into your project root before building.")
