#!/usr/bin/env python3
"""Write ~/.config/openbox/rc.xml from the distro default with the Cathedral look and Super keybinds.

Starting from /etc/xdg/openbox/rc.xml keeps every mouse binding and default openbox ships;
only theme, fonts, title layout and a few Super shortcuts change.
"""
import os
import xml.etree.ElementTree as ET

NS = "http://openbox.org/3.4/rc"
ET.register_namespace("", NS)
SRC = "/etc/xdg/openbox/rc.xml"
DST = os.path.expanduser("~/.config/openbox/rc.xml")
KEYS = [
    ("W-Return", "Execute", "xfce4-terminal"),
    ("W-b", "Execute", "browser"),
    ("W-q", "Close", None),
    ("W-f", "ToggleMaximizeFull", None),
    ("W-h", "ToggleShowDesktop", None),
]


def q(tag: str) -> str:
    return f"{{{NS}}}{tag}"


def main() -> None:
    tree = ET.parse(SRC)
    root = tree.getroot()
    theme = root.find(q("theme"))
    theme.find(q("name")).text = "Cathedral"
    theme.find(q("titleLayout")).text = "LIMC"
    for font in theme.findall(q("font")):
        font.find(q("name")).text = "Inter"
        font.find(q("size")).text = "10" if font.get("place") in ("ActiveWindow", "InactiveWindow", "MenuItem") else "11"
        font.find(q("weight")).text = "Normal"
    focus = root.find(q("focus"))
    if focus is not None and focus.find(q("focusNew")) is not None:
        focus.find(q("focusNew")).text = "yes"
    placement = root.find(q("placement"))
    if placement is not None and placement.find(q("policy")) is not None:
        placement.find(q("policy")).text = "Smart"
    keyboard = root.find(q("keyboard"))
    bound = {k.get("key") for k in keyboard.findall(q("keybind"))}
    for key, action, command in KEYS:
        if key in bound:
            continue
        kb = ET.SubElement(keyboard, q("keybind"), {"key": key})
        act = ET.SubElement(kb, q("action"), {"name": action})
        if command:
            ET.SubElement(act, q("command")).text = command
    os.makedirs(os.path.dirname(DST), exist_ok=True)
    tree.write(DST, encoding="UTF-8", xml_declaration=True)
    print(f"wrote {DST}")


if __name__ == "__main__":
    main()
