"""Render the debugger-coverage chart used in the README."""

from PIL import Image, ImageDraw, ImageFont

W, H = 1480, 980
BG = (10, 14, 22)
CARD = (18, 24, 36)
LINE = (42, 54, 74)
TEXT = (236, 241, 248)
MUTED = (154, 168, 188)
BEFORE = (92, 108, 136)
AFTER = (45, 212, 191)
AMBER = (245, 166, 35)

# After = engines that fully support the job / engines that job applies to.
# Static jobs apply to radare2. Live jobs apply to x64dbg, cdb, and Frida.
# 67 = x64dbg and cdb only. Frida does not step, pause, or fully control threads.
# Assembly reading has an explain tool; its accuracy was not measured.
ROWS = [
    ("Disassemble", 0, 100),
    ("Control-flow graph", 0, 100),
    ("Cross-references", 0, 100),
    ("Strings", 20, 100),
    ("Hex dump", 20, 100),
    ("Breakpoints", 0, 67),
    ("Step and pause", 0, 67),
    ("Registers", 0, 67),
    ("Call stack", 0, 67),
    ("Live memory", 0, 100),
    ("Thread control", 0, 67),
    ("Assembly reading", 10, None),
]


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    path = "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf"
    return ImageFont.truetype(path, size)


def main() -> None:
    image = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((28, 24, W - 28, H - 24), 28, fill=CARD, outline=LINE, width=2)

    draw.text((64, 52), "Agent debugger coverage", font=font(40, True), fill=TEXT)
    draw.text(
        (64, 108),
        "Engines that fully support each job. 100 is not a success-rate benchmark.",
        font=font(22),
        fill=MUTED,
    )

    scored = [row for row in ROWS if row[2] is not None]
    before_avg = round(sum(row[1] for row in scored) / len(scored))
    after_avg = round(sum(row[2] for row in scored) / len(scored))
    draw.rounded_rectangle((64, 164, 430, 268), 16, fill=(28, 36, 52))
    draw.text((84, 178), "Before Conduit", font=font(18), fill=MUTED)
    draw.text((84, 206), f"{before_avg}%", font=font(42, True), fill=BEFORE)
    draw.rounded_rectangle((450, 164, 860, 268), 16, fill=(16, 48, 46))
    draw.text((470, 178), "Fully supported", font=font(18), fill=AFTER)
    draw.text((470, 206), f"{after_avg}%", font=font(42, True), fill=AFTER)
    draw.rounded_rectangle((880, 164, 1410, 268), 16, fill=(48, 36, 16))
    draw.text((900, 178), "Before column", font=font(18), fill=AMBER)
    draw.text((900, 206), "estimate", font=font(42, True), fill=AMBER)

    top = 300
    row_h = 50
    bar_x = 340
    bar_w = 900
    for index, (label, before, after) in enumerate(ROWS):
        y = top + index * row_h
        draw.text((64, y + 10), label, font=font(20), fill=TEXT)
        track = (32, 40, 56)
        draw.rounded_rectangle((bar_x, y + 8, bar_x + bar_w, y + 22), 6, fill=track)
        draw.rounded_rectangle((bar_x, y + 26, bar_x + bar_w, y + 40), 6, fill=track)
        if before:
            draw.rounded_rectangle((bar_x, y + 8, bar_x + max(8, int(bar_w * before / 100)), y + 22), 6, fill=BEFORE)
        if after is None:
            draw.text((bar_x + 8, y + 22), "accuracy not measured", font=font(14), fill=MUTED)
        else:
            draw.rounded_rectangle((bar_x, y + 26, bar_x + int(bar_w * after / 100), y + 40), 6, fill=AFTER)
        draw.text((bar_x + bar_w + 16, y + 4), f"{before}%", font=font(16), fill=BEFORE)
        draw.text((bar_x + bar_w + 16, y + 24), "n/a" if after is None else f"{after}%", font=font(16), fill=MUTED if after is None else AFTER)

    draw.rounded_rectangle((64, 918, 92, 938), 4, fill=BEFORE)
    draw.text((104, 912), "Before  —  shell only, no debugger tool", font=font(18), fill=MUTED)
    draw.rounded_rectangle((640, 918, 668, 938), 4, fill=AFTER)
    draw.text((680, 912), "67%  —  x64dbg and cdb only; Frida does not", font=font(18), fill=MUTED)

    image.save("assets/capability-coverage.png", "PNG")


if __name__ == "__main__":
    main()
