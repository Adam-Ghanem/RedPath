"""Render the GitHub social-preview card for RedPath."""

from pathlib import Path
from random import Random

from PIL import Image, ImageDraw, ImageFilter, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "assets" / "social-preview.png"
LOGO = ROOT / "assets" / "redpath-logo.png"
WIDTH, HEIGHT = 1280, 640


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
    return ImageFont.truetype(name, size)


def main() -> None:
    random = Random(17)
    image = Image.new("RGB", (WIDTH, HEIGHT), "#0d1012")
    draw = ImageDraw.Draw(image)

    # Restrained analogue grain; deterministic so this visual remains reproducible.
    grain = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 0))
    grain_draw = ImageDraw.Draw(grain)
    for _ in range(15000):
        x, y = random.randrange(WIDTH), random.randrange(HEIGHT)
        value = random.choice((20, 25, 32, 38, 44))
        grain_draw.point((x, y), fill=(value, value, value, random.randrange(10, 32)))
    image = Image.alpha_composite(image.convert("RGBA"), grain.filter(ImageFilter.GaussianBlur(0.35)))
    draw = ImageDraw.Draw(image)

    # Evidence-board route: intentionally decorative, never a claim about a real network.
    route = [(510, 128), (660, 78), (840, 128), (1080, 94), (1170, 190), (1050, 320), (1140, 470), (900, 535), (680, 475), (518, 535)]
    draw.line(route, fill="#5d2428", width=2, joint="curve")
    for x, y in route:
        draw.ellipse((x - 7, y - 7, x + 7, y + 7), outline="#d3373f", width=2)
        draw.ellipse((x - 2, y - 2, x + 2, y + 2), fill="#d3373f")

    # Two clipped paper records balance the left rail without borrowing any external imagery.
    draw.polygon([(42, 88), (228, 55), (247, 192), (58, 218)], fill="#272625", outline="#68615a")
    draw.line((70, 119, 201, 97), fill="#d3373f", width=3)
    draw.text((69, 132), "CASE FILE", font=font(17, bold=True), fill="#d9d1c6")
    draw.text((69, 161), "REDPATH / SYNTHETIC LAB", font=font(10), fill="#aca397")
    draw.polygon([(50, 415), (244, 382), (263, 544), (74, 572)], fill="#242322", outline="#625d57")
    draw.text((76, 441), "EVIDENCE NOTE", font=font(13, bold=True), fill="#d8d0c5")
    draw.text((76, 475), "INITIAL ACCESS", font=font(11), fill="#a79d91")
    draw.text((76, 499), "LATERAL MOVEMENT", font=font(11), fill="#a79d91")
    draw.text((76, 523), "DETECTION GAP", font=font(11), fill="#d3373f")

    # Crop transparent padding, then scale the canonical mark without redrawing its geometry.
    logo = Image.open(LOGO).convert("RGBA")
    alpha_box = logo.getchannel("A").getbbox()
    if alpha_box:
        logo = logo.crop(alpha_box)
    logo.thumbnail((310, 480), Image.Resampling.LANCZOS)
    image.alpha_composite(logo, (248, 80))

    draw = ImageDraw.Draw(image)
    cream = "#f1eee7"
    muted = "#bdb8af"
    draw.text((605, 195), "RedPath", font=font(100, bold=True), fill=cream)
    draw.line((610, 322, 1178, 322), fill="#df343c", width=3)
    draw.ellipse((1170, 314, 1186, 330), fill="#df343c")
    draw.text((605, 355), "See the path. Prove the gap.", font=font(39, bold=True), fill=cream)
    draw.text((607, 416), "Attack-path intelligence for SOC teams", font=font(25), fill=muted)
    draw.text((607, 492), "SAFE  /  SYNTHETIC  /  EVIDENCE-LED", font=font(13, bold=True), fill="#d3373f")

    image.convert("RGB").save(OUTPUT, quality=95, optimize=True)


if __name__ == "__main__":
    main()
