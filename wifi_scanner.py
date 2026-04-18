#!/usr/bin/env python3
"""
WiFi Scanner for WSL2 Ubuntu
Scans available access points and displays signal strength as a bar chart,
along with SSID and encryption type.

Primary backend : netsh.exe (Windows host, via WSL2 interop)
Fallback backend: nmcli   (native Linux / NetworkManager)
"""

import re
import subprocess
import sys
from dataclasses import dataclass


# ── ANSI helpers ─────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class AccessPoint:
    ssid:       str
    signal:     int   # 0-100 %
    auth:       str
    encryption: str
    bssid:      str = ""
    channel:    str = ""
    radio:      str = ""


# ── Bar-chart renderer ────────────────────────────────────────────────────────

def signal_bar(pct: int, width: int = 24) -> str:
    filled = max(0, min(width, round(pct / 100 * width)))
    empty  = width - filled
    color  = GREEN if pct >= 67 else (YELLOW if pct >= 34 else RED)
    return f"{color}{'█' * filled}{DIM}{'░' * empty}{RESET}"


# ── netsh backend (WSL2 / Windows) ────────────────────────────────────────────

def _run_netsh() -> str:
    res = subprocess.run(
        ["netsh.exe", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True, text=True, timeout=20,
        encoding="utf-8", errors="replace",
    )
    return res.stdout if res.returncode == 0 else ""


def _parse_netsh(raw: str) -> list[AccessPoint]:
    aps: list[AccessPoint] = []
    cur: dict = {}
    in_bssid1 = False

    def _flush():
        if cur.get("ssid") is not None and "signal" in cur:
            aps.append(AccessPoint(
                ssid       = cur.get("ssid") or "<hidden>",
                signal     = cur["signal"],
                auth       = cur.get("auth", "Unknown"),
                encryption = cur.get("enc",  "Unknown"),
                bssid      = cur.get("bssid", ""),
                channel    = cur.get("ch",    ""),
                radio      = cur.get("radio", ""),
            ))

    for line in raw.splitlines():
        s = line.strip()

        m = re.match(r"SSID\s+\d+\s*:\s*(.*)", s)
        if m:
            _flush()
            cur = {"ssid": m.group(1).strip()}
            in_bssid1 = False
            continue

        m = re.match(r"Authentication\s*:\s*(.*)", s, re.I)
        if m:
            cur["auth"] = m.group(1).strip()
            continue

        m = re.match(r"Encryption\s*:\s*(.*)", s, re.I)
        if m:
            cur["enc"] = m.group(1).strip()
            continue

        m = re.match(r"BSSID\s+(\d+)\s*:\s*(.*)", s, re.I)
        if m:
            in_bssid1 = (m.group(1) == "1")
            if in_bssid1:
                cur["bssid"] = m.group(2).strip()
            continue

        if in_bssid1:
            m = re.match(r"Signal\s*:\s*(\d+)%", s, re.I)
            if m:
                cur["signal"] = int(m.group(1))
                continue
            m = re.match(r"Radio type\s*:\s*(.*)", s, re.I)
            if m:
                cur["radio"] = m.group(1).strip()
                continue
            m = re.match(r"Channel\s*:\s*(.*)", s, re.I)
            if m:
                cur["ch"] = m.group(1).strip()
                continue

    _flush()
    return aps


def scan_netsh() -> list[AccessPoint]:
    try:
        return _parse_netsh(_run_netsh())
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return []


# ── nmcli backend (native Linux / fallback) ───────────────────────────────────

def _run_nmcli() -> str:
    res = subprocess.run(
        ["nmcli", "--terse", "--fields",
         "SSID,SIGNAL,SECURITY,BSSID,CHAN,MODE", "device", "wifi", "list"],
        capture_output=True, text=True, timeout=20,
    )
    return res.stdout if res.returncode == 0 else ""


def _parse_nmcli(raw: str) -> list[AccessPoint]:
    aps: list[AccessPoint] = []
    for line in raw.splitlines():
        # nmcli -t escapes ':' inside values as '\:' – unescape per field
        parts = re.split(r"(?<!\\):", line)
        parts = [p.replace(r"\:", ":") for p in parts]
        if len(parts) < 3:
            continue
        ssid   = parts[0].strip() or "<hidden>"
        try:
            signal = int(parts[1].strip())
        except ValueError:
            signal = 0
        auth   = parts[2].strip() or "Open"
        bssid  = parts[3].strip() if len(parts) > 3 else ""
        ch     = parts[4].strip() if len(parts) > 4 else ""
        aps.append(AccessPoint(
            ssid=ssid, signal=signal,
            auth=auth, encryption="",
            bssid=bssid, channel=ch,
        ))
    return aps


def scan_nmcli() -> list[AccessPoint]:
    try:
        return _parse_nmcli(_run_nmcli())
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return []


# ── Encryption label ──────────────────────────────────────────────────────────

def enc_label(auth: str, enc: str) -> str:
    s = f"{auth} {enc}".upper()
    if "WPA3" in s:
        return f"{GREEN}WPA3{RESET}"
    if "WPA2" in s:
        return f"{GREEN}WPA2{RESET}"
    if "WPA"  in s:
        return f"{YELLOW}WPA {RESET}"
    if "WEP"  in s:
        return f"{RED}WEP {RESET}"
    return f"{RED}OPEN{RESET}"


# ── Display ───────────────────────────────────────────────────────────────────

BAR_W   = 24
SSID_W  = 30
LINE_W  = 82

def display(aps: list[AccessPoint]) -> None:
    aps.sort(key=lambda a: a.signal, reverse=True)

    print()
    print(f"{BOLD}{CYAN}{'WiFi Scanner – Access Points':^{LINE_W}}{RESET}")
    print(f"{DIM}{'─' * LINE_W}{RESET}")
    print(
        f"{BOLD}"
        f"{'SSID':<{SSID_W}} "
        f"{'Signal strength':<{BAR_W + 7}} "
        f"{'Enc ':5}"
        f"{'Security':<20}"
        f"{'Ch':>4}"
        f"{RESET}"
    )
    print(f"{DIM}{'─' * LINE_W}{RESET}")

    for ap in aps:
        ssid    = (ap.ssid[:SSID_W - 1] + "…") if len(ap.ssid) >= SSID_W else ap.ssid
        bar     = signal_bar(ap.signal, BAR_W)
        elabel  = enc_label(ap.auth, ap.encryption)
        auth_s  = ap.auth[:19]
        ch      = ap.channel or "–"
        print(
            f"{WHITE}{ssid:<{SSID_W}}{RESET} "
            f"{bar} {BOLD}{ap.signal:>3}%{RESET}  "
            f"{elabel} "
            f"{DIM}{auth_s:<20}{RESET}"
            f"{CYAN}{ch:>4}{RESET}"
        )

    print(f"{DIM}{'─' * LINE_W}{RESET}")
    print(f"{DIM}{len(aps)} access point(s) found{RESET}")
    print()
    print(
        f"  Signal : {GREEN}{'█'*6}{RESET} Strong (≥67%)  "
        f"{YELLOW}{'█'*6}{RESET} Medium (34-66%)  "
        f"{RED}{'█'*6}{RESET} Weak (<34%)"
    )
    print(
        f"  Enc    : {GREEN}WPA2/WPA3{RESET} secure  "
        f"{YELLOW}WPA{RESET} fair  "
        f"{RED}WEP / OPEN{RESET} insecure"
    )
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    print(f"{CYAN}Scanning for WiFi networks…{RESET}")

    aps    = scan_netsh()
    source = "netsh.exe (Windows host)"

    if not aps:
        aps    = scan_nmcli()
        source = "nmcli (NetworkManager)"

    if not aps:
        print(f"\n{RED}No access points found.{RESET}")
        print(
            "\nTroubleshooting:\n"
            "  WSL2 : ensure Windows WiFi is on and netsh.exe is reachable\n"
            "         (test with: netsh.exe wlan show networks)\n"
            "  Linux: sudo apt install network-manager\n"
            "         sudo systemctl start NetworkManager\n"
            "         sudo nmcli device wifi list\n"
        )
        sys.exit(1)

    print(f"{DIM}Backend: {source}{RESET}")
    display(aps)


if __name__ == "__main__":
    main()
