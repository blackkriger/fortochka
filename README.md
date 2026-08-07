[![en](https://img.shields.io/badge/lang-en-red)](README.en.md) [![ru](https://img.shields.io/badge/lang-ru-green)](README.md) <img src="cmd/fortochka/icon.png" width="64" align="right" alt="fortochka icon">

# fortochka

Выборочный split-туннель для Windows поверх **твоего** WireGuard или AmneziaWG. Заблокированные сайты и выбранные приложения идут **через** туннель, всё остальное — напрямую. 

## Что это

fortochka живёт в системном трее и состоит из двух частей:

- **Движок** — служба Windows (LocalSystem): userspace-туннель wg/awg, локальный SOCKS5/HTTP-прокси + PAC, правила маршрутизации и перехват по приложениям (WinDivert).
- **Трей** — маленькое меню без прав администратора, общается с движком по локальному пути. 

Служба работает в фоне и стартует с Windows; трей можно закрыть — движок продолжит работать.

## Как работает

```
Telegram ────SOCKS5───┐
Browser  ─────PAC─────┼─→ proxy → rules ─ direct → OZON, LAN, …
claude.exe ─WinDivert─┘                  └ wg/awg → blocked sites 
```

- **Правила решают по каждому адресу: напрямую или в туннель.** Заблокированные домены/IP (автоматически подтягиваются списки [Re:filter](https://github.com/1andrevich/Re-filter-lists)), плюсом твой список, идут через WG; остальное — напрямую. 
- **Браузер** идёт по системному PAC → на локальный прокси (`127.0.0.1:1080`).
- **Приложения** можно завернуть целиком через WinDivert — *весь* TCP выбранного процесса уходит в туннель, без настройки прокси.

## Установка

1. Скачай [последний релиз](https://github.com/blackkriger/fortochka/releases/latest) и запусти `fortochka.exe`. При первом запуске он сам поставит службу и автозапуск (разовый запрос прав администратора), а в трее появится **f** меню. 
2. Трей → **Import tunnel config…** → выбери свой wg или awg `.conf` 

## Меню в трее

```
Connected                      статус: Disconnected / Connecting… / No config imported / Engine off
Disconnect                     подключить / отключить туннель
───
Import tunnel config…
Connection info ▸              адреса Server / PAC / SOCKS5
───
Route address through tunnel…  редактировать список доменов/IP для туннеля
Route app through tunnel ▸     отметить приложения — весь их трафик в туннель
Service ▸                      Install service — поставить движок, либо «fortochka on — click to turn off» (стоп + удаление)
                               Start with Windows — автозапуск с системой
More ▸                         Update automatically — ставить новые релизы сразу
                               Open program folder — папка данных
                               Show / hide log — окно логов
───
Quit                           закрыть трей (движок продолжит работать, если не удалён)
```

<img src="cmd/fortochka/icon.png" width="22" align="absmiddle"> отключён &nbsp;&nbsp;
<img src="cmd/fortochka/icon-connecting.png" width="22" align="absmiddle"> подключается &nbsp;&nbsp;
<img src="cmd/fortochka/icon-connected.png" width="22" align="absmiddle"> подключён

## Правила маршрутизации

Твой список — `C:\ProgramData\fortochka\rules.txt` (трей → **Route address through tunnel…** открывает его). По одной записи на строку, `#` — комментарий. Понимает:

- домены — `claude.ai` (и поддомены тоже)
- IP / CIDR — `198.51.100.7`, `203.0.113.0/24`
- полный URL / host:port — `http://198.51.100.7:8082/` (схема, порт и путь отбрасываются)
- префикс `!` — принудительно **напрямую**, мимо туннеля, даже если адрес есть в блок-листе 
- имя сервиса — `youtube`, `instagram` — разворачивается во все его домены, чтобы части сервиса не разъехались по разным маршрутам

Сохранение подхватывается на лету — подходящие соединения сразу переезжают на новый маршрут.

Сервис — это больше, чем его очевидный домен: YouTube, например, тянет превью, аватарки и API плеера с других адресов. Пропишешь только `youtube.com` — сайт заработает наполовину: страница одним путём, API плеера другим. Для этого и нужны сервисы: `!youtube` уводит напрямую всё целиком. 

Приложения из Microsoft Store работают внутри движка браузера, а не отдельным процессом, поэтому в списке приложений их нет — а завернуть браузер целиком значит завернуть всё. Их маршрутизируют адресом: для приложения Instagram одна запись `instagram` покрывает и страницу, и медиа, и CDN. 

## Сборка

```powershell
.\build.ps1              # builds the self-contained fortochka.exe
.\build.ps1 -Resources   # also regenerates the icons + the .syso (icon + manifest)
```

Требуется Go (см. `go.mod`) и Windows. `WinDivert.dll` + `WinDivert64.sys` вшиваются из `internal/windivert/bin` в exe и распаковываются в `C:\ProgramData\fortochka` в рантайме — на выходе должен быть один файл.

Перехват пакетов работает на [WinDivert](https://github.com/basil00/WinDivert). Туннель AmneziaWG — на [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go).
