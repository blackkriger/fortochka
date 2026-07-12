<img src="cmd/fortochka/icon.png" width="64" align="right" alt="fortochka icon">

[![en](https://img.shields.io/badge/lang-en-red)](README.en.md) [![ru](https://img.shields.io/badge/lang-ru-green)](README.md)

# fortochka

Выборочный split-туннель для Windows поверх **твоего** WireGuard. Заблокированные сайты и выбранные приложения идут **через** туннель, всё остальное — напрямую.

## Что это

fortochka живёт в системном трее и состоит из двух частей:

- **Движок** — служба Windows (LocalSystem): userspace-туннель WireGuard, локальный SOCKS5/HTTP-прокси + PAC, правила маршрутизации и перехват по приложениям (WinDivert).
- **Трей** — маленькое меню без прав администратора, общается с движком через локальный named pipe.

Служба работает в фоне и стартует с Windows; трей можно закрыть — движок продолжит работать.

## Как работает

```
Telegram ────SOCKS5──┐
Browser  ─────PAC─────┼─→ proxy → rules ─ direct → OZON, LAN, …
claude.exe ─WinDivert─┘                  └ wg → your server → blocked sites
```

- **Правила решают по каждому адресу: напрямую или в туннель.** Заблокированные домены/IP (автоматически подтягиваются списки [Re:filter](https://github.com/1andrevich/Re-filter-lists)), плюсом твой список, идут через WG; остальное — напрямую. 
- **Браузер** идёт по системному PAC → на локальный прокси (`127.0.0.1:1080`).
- **Приложения** можно завернуть целиком через WinDivert — *весь* TCP выбранного процесса уходит в туннель, без настройки прокси.

## Меню в трее

```
Connected                      status: Disconnected / Connecting… / No config imported / Engine off
Disconnect                     connect / disconnect the tunnel
───
Import WG config…
Connection info ▸              Server / PAC / SOCKS5 addresses
───
Route address through tunnel…  edit the routed domain/IP list
Route app through tunnel ▸     tick running apps to tunnel whole
Service ▸                      start/stop
                               Start with Windows
                               Uninstall
More ▸                         Open program folder
                               Show / hide log
───
Quit                           close the tray (engine keeps running, unless uninstalled)
```

<img src="cmd/fortochka/icon.png" width="22" align="absmiddle"> отключён &nbsp;&nbsp;
<img src="cmd/fortochka/icon-connecting.png" width="22" align="absmiddle"> подключается &nbsp;&nbsp;
<img src="cmd/fortochka/icon-connected.png" width="22" align="absmiddle"> подключён

## Правила маршрутизации

Твой список — `C:\ProgramData\fortochka\rules.txt` (трей → **Route address through tunnel…** открывает его). По одной записи на строку, `#` — комментарий. Понимает:

- домены — `claude.ai` (и поддомены тоже)
- IP / CIDR — `198.51.100.7`, `203.0.113.0/24`
- полный URL / host:port — `http://198.51.100.7:8082/` (схема, порт и путь отбрасываются)

Сохранение подхватывается на лету — подходящие соединения сразу переезжают на новый маршрут.

## Сборка

```powershell
.\build.ps1              # builds the self-contained fortochka.exe
.\build.ps1 -Resources   # also regenerates the icons + the .syso (icon + manifest)
```

Требуется Go (см. `go.mod`) и Windows. `WinDivert.dll` + `WinDivert64.sys` вшиваются из `internal/windivert/bin` в exe и распаковываются в `C:\ProgramData\fortochka` в рантайме — на выходе должен быть один файл.

Перехват пакетов работает на [WinDivert](https://github.com/basil00/WinDivert).
