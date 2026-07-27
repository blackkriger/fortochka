<img src="cmd/fortochka/icon.png" width="64" align="right" alt="fortochka icon">

[![en](https://img.shields.io/badge/lang-en-red)](README.en.md) [![ru](https://img.shields.io/badge/lang-ru-green)](README.md)

# fortochka

Selective split-tunnel for Windows over **your own** WireGuard or AmneziaWG connection. Blocked sites and chosen apps go **through** the tunnel; everything else stays on the direct connection. 

## What it is

fortochka lives in the system tray and splits into two parts:

- **Engine** — a Windows service (LocalSystem) that runs a userspace WireGuard/AmneziaWG tunnel, a local SOCKS5/HTTP proxy + PAC, the routing rules, and per-app interception (WinDivert).
- **Tray** — a small, non-elevated UI that talks to the engine over a local named pipe.

The engine runs in the background and starts with Windows by default. 

## How it works

```
Telegram ────SOCKS5───┐
Browser  ─────PAC─────┼─→ proxy → rules ─ direct → OZON, LAN, …
claude.exe ─WinDivert─┘                  └ wg/awg → blocked sites 
```

- **Rules decide direct vs tunnel per destination.** Blocked domains/IPs (auto-fetched [Re:filter](https://github.com/1andrevich/Re-filter-lists) lists) plus your own list go through the tunnel; the default is direct.
- **Browser** follows the system PAC → the local proxy (`127.0.0.1:1080`).
- **Apps** can be routed whole via WinDivert — *all* of a chosen process's TCP goes through the tunnel, no proxy settings required.

## Install

1. Download the [latest release](https://github.com/blackkriger/fortochka/releases/latest) and run `fortochka.exe`. On first launch it installs the engine service and enables Start with Windows (a one-time admin prompt); the `f` menu will appear in the tray.
2. Tray → **Import tunnel config…** → pick your WireGuard or AmneziaWG `.conf`

## The tray menu

```
<status>                       Disconnected / Connecting… / No config imported / Engine off
Connect / Disconnect           connect / disconnect the tunnel
───
Import tunnel config…
Connection info ▸              Server / PAC / SOCKS5 addresses
───
Route address through tunnel…  edit the routed domain/IP list
Route app through tunnel ▸     tick running apps to tunnel whole
Service ▸                      Install service, or "fortochka on — click to turn off" (stop + remove)
                               Start with Windows — boot autostart
More ▸                         Open program folder
                               Show / hide log console
───
Quit                           close the tray (the engine keeps running)
```

<img src="cmd/fortochka/icon.png" width="22" align="absmiddle"> disconnected &nbsp;&nbsp;
<img src="cmd/fortochka/icon-connecting.png" width="22" align="absmiddle"> connecting &nbsp;&nbsp;
<img src="cmd/fortochka/icon-connected.png" width="22" align="absmiddle"> connected

## Routing rules

Your custom list lives in `C:\ProgramData\fortochka\rules.txt` (Tray → **Route address through tunnel…** opens it). One entry per line, `#` for comments. It accepts:

- domains — `claude.ai` (also matches subdomains)
- IPs / CIDRs — `198.51.100.7`, `203.0.113.0/24`
- full URLs / host:port — `http://198.51.100.7:8082/` (scheme, port and path ignored)
- prefix a line with `!` to force it **DIRECT** — bypasses the tunnel even if a fetched block list would route it through 

Saving reloads live and immediately re-routes matching connections.

Discord domains are pinned direct in the build (they tunnel poorly — voice latency), so pair fortochka with a DPI-bypass tool if your ISP throttles them.

## Build

```powershell
.\build.ps1              # builds the self-contained fortochka.exe
.\build.ps1 -Resources   # also regenerates the icons + the .syso (icon + manifest)
```

Requires Go (see `go.mod`) and Windows. `WinDivert.dll` + `WinDivert64.sys` are embedded from `internal/windivert/bin` into the exe and unpacked to `C:\ProgramData\fortochka` at runtime — the build output is a single file.

Packet capture is powered by [WinDivert](https://github.com/basil00/WinDivert). The AmneziaWG tunnel runs on [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go).
