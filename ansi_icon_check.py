import re
import sys

TAG_RE = re.compile(r"\[(?P<attrs>[^\]]+)\](?P<text>.*?)\[/\]", re.DOTALL)
HEX_RE = re.compile(r"#([0-9a-fA-F]{6})")


def ansi_seq(color_hex: str, bold: bool) -> str:
    r = int(color_hex[0:2], 16)
    g = int(color_hex[2:4], 16)
    b = int(color_hex[4:6], 16)
    parts = []
    if bold:
        parts.append("1")
    parts.append(f"38;2;{r};{g};{b}")
    return "\x1b[" + ";".join(parts) + "m"


def parse_and_print(s: str) -> None:
    m = TAG_RE.fullmatch(s.strip())
    if not m:
        print("Input must be like: [#RRGGBB bold]TEXT[/]", file=sys.stderr)
        sys.exit(1)

    attrs = m.group("attrs")
    text = m.group("text")

    hex_m = HEX_RE.search(attrs)
    if not hex_m:
        print("Missing hex color like #123456", file=sys.stderr)
        sys.exit(1)

    color_hex = hex_m.group(1)
    bold = "bold" in attrs.split()

    seq = ansi_seq(color_hex, bold)
    reset = "\x1b[0m"
    print(f"{seq}{text}{reset}")


if __name__ == "__main__":
    parse_and_print("[#3490de][/]")
    parse_and_print("[#FFFFFF][/]")
    parse_and_print("[#f08a5d][/]")
    print("\x1b[1;3;4;38;2;255;80;0;48;2;30;30;30mHello\x1b[0m\n")
    print("\x1b[9mstrikethrough\x1b[29m normal")
    from wcwidth import wcwidth
    print(wcwidth("\uf17c"), wcwidth("\U000F0A21"))
    print("󰨡")



