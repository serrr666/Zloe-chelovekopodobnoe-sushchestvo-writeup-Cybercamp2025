# Злое человекоподобное существо разбор таска с CyberCamp 2025
## Ход расследования

### 1. Первоначальная активность и подготовка стенда

В архиве `Logs` находятся 20 непустых журналов EVTX (>68кбайт). События поступают с хоста `DESKTOP-MGH9F2V`, пользователь `DESKTOP-MGH9F2V\win10user`

Для анализа достаточно будет рассмотреть журналы Security/Sysmon/System

В журнале `System` события 7045, записи #385–#386, фиксируют установку Sysmon и SysmonDrv. В `Microsoft-Windows-Sysmon%4Operational.evtx` событие 16, запись #1, в `10:01:44.980` указывает применение `C:\Users\win10user\Downloads\sysmonconfig-export.xml`. В `10:01:45.288` служба Sysmon запускается, событие 4, #2. Это настройка наблюдения до доставки подозрительного файла. Сам XML в архиве отсутствует, поэтому его фильтры проверить нельзя.

В `10:01:53` пользователь открывает `secpol.msc`, в `10:02:21` — `gpedit.msc`. Security 4719, записи #605–#626, отражает 22 изменения аудита в `10:02:03–10:02:15`. GroupPolicy показывает применение локальных политик до запуска исследуемого EXE. Это согласуется с подготовкой стенда; содержимое политик не представлено, поэтому отключение защиты атакующим из этих событий не следует.

### 2. Доставка файла через VirtualBox

В `10:03:17.796` Sysmon 11, #730, фиксирует создание файла процессом `C:\Windows\System32\VBoxTray.exe`, PID 836:

```text
C:\Users\WIN10U~1\AppData\Local\Temp\VirtualBox Dropped Files\2025-09-16T10_03_17.796611900Z\смета_27.05.2024.exe
```

Это след переноса файла в виртуальную машину. VBoxTray здесь создаёт файл, а не запускает его. Почтового письма, браузерной загрузки или другого первоначального канала реальной кампании в архиве нет.

В `10:03:24.380` Explorer запускает `"C:\Program Files\Windows Defender\MSASCui.exe" /enable /as`, Sysmon 1, #735, Security 4688, #733. Это старый интерфейс Defender версии `4.8.10240.16384`, соответствующий Windows 10 build 10240. Он запущен до исполнения «сметы» и не является её потомком. Доказательств отключения Defender этой командой нет.

### 3. Установка WinRAR

В `10:03:56.591` VBoxTray переносит установщик `winrar-x64-713.exe`, Sysmon 11, #1215. В `10:04:00.734` пользователь запускает его из Downloads, Sysmon 1, #1231, с уровнем целостности High.

В `10:04:00.800` `svchost.exe` записывает сведения об установщике в `AppCompatFlags\Compatibility Assistant\Store`, Sysmon 13, #1232. Это след учёта исполнения Program Compatibility Assistant, а не механизм автозапуска.

В `10:04:02.643` установщик создаёт `C:\Program Files\WinRAR\RarExtInstaller.exe`, Sysmon 11, #1252. Отдельное исполнение этого файла не найдено. Далее наблюдаются `uninstall.exe /setup`, регистрация расширений и создание ярлыков WinRAR в Shell-Core, записи #717–#724. Эти действия согласуются с установкой архиватора.

WinRAR важен для следующего этапа: установленная утилита действительно используется при распаковке подозрительного архива. Эксплуатация уязвимости WinRAR по этим данным не установлена.

### 4. Исполнение смета_27.05.2024.exe

В `10:04:13.205` Explorer PID 3084 запускает `C:\Users\win10user\AppData\Local\Temp\смета_27.05.2024.exe`, PID 504. Это Sysmon 1, #1380, и Security 4688, #761. Как файл оказался из VirtualBox-каталога в корне Temp, события прямо не показывают.

Хеши из Sysmon 1:

```text
MD5: 7CF97A76ACC5965D3106931097CDDEE6
SHA256: 6E3F5E13FD9D0BA45A64DFF1577F0CFBE53D99AACBE50A9B009E811AC9F4C846
IMPHASH: DCAF48C1F10B0EFA0A4472200F3850ED
```

В `10:04:13.286` EXE создаёт `VCRUNTIME140.dll` в `C:\Users\WIN10U~1\AppData\Local\Temp\_MEI5042`, Sysmon 11, #1382. Всего в этом каталоге зафиксировано 46 событий создания файлов, включая `libcrypto-3.dll`, `python313.dll` и `ucrtbase.dll`. Паттерн согласуется с распаковкой Python-приложения через PyInstaller one-file. Создание DLL не доказывает DLL sideloading: события загрузки модулей Sysmon 7 отсутствуют. Поведение `_MEI…` описано в [документации PyInstaller](https://pyinstaller.org/en/stable/operating-mode.html).

В `10:04:14.725` PID 504 создаёт второй экземпляр того же EXE, PID 1972, Sysmon 1, #1436. Оба процесса завершаются в `10:04:15` с кодом 0, Security 4689, #763–#764.

Имя `смета_27.05.2024.exe` встречается в [исследовании Loki](https://securelist.ru/loki-agent-for-mythic/110361/), но опубликованный там MD5 — `375CFE475725CAA89EDF6D40ACD7BE70`. Он отличается от локального хеша.

Пользовательское исполнение подозрительного файла соответствует вероятному T1204.002. При этом родительские связи не показывают, что этот EXE запустил следующую архивную цепочку.

### 5. Поиск Resume.rar и запуск PowerShell

В `10:04:34.827` Explorer запускает CMD PID 5088 с рабочей директорией `C:\Users\Public\Libraries\`. Это Sysmon 1, #1582, и Security 4688, #767. Команда из Security:

```text
"C:\Windows\system32\cmd.exe" /c where /r C:\Users\win10user\AppData\Local\Temp Resume.rar | ( set /p "v=" && @call "C:\Program Files\WinRAR\WinRAR.exe" -y x %v% . ) && powershell -ExecutionPolicy Bypass -File Passport\20.ps1
```

`where.exe` ищет архив в Temp. Найденный путь передаётся WinRAR, который распаковывает `C:\Users\win10user\AppData\Local\Temp\Resume.rar` в текущую директорию. В `10:04:35.942` WinRAR PID 4884 создаёт `C:\Users\Public\Libraries\Passport\20.ps1`, Sysmon 11, #1586. Архиватор завершается с кодом 0, Security 4689, #773.

В `10:04:36.206` CMD запускает PowerShell PID 4216:

```text
powershell -ExecutionPolicy Bypass -File Passport\20.ps1
```

По форме команды и родителю Explorer вероятен запуск через LNK. Сам ярлык в архиве отсутствует, его имя локальными событиями не установлено. Пароль или шифрование архива также не подтверждены.

Это соответствует T1059.003, T1059.001 и распаковке файлов T1140. `ExecutionPolicy Bypass` не является самостоятельным доказательством отключения антивируса.

### 6. Попытка непрямого запуска через conhost и документ-приманка

В `10:04:38.376766` PowerShell создаёт conhost PID 796. Событие найдено в Security 4688, #776; в Sysmon 1 оно отсутствует:

```text
"C:\Windows\system32\conhost.exe" --headless C:\Users\Public\Libraries\Passport\19.jpg
```

Через примерно 17 мс, в `10:04:38.393948`, conhost завершается с `0xc000000d`, Security 4689, #778. Это [STATUS_INVALID_PARAMETER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55). Успешное исполнение `19.jpg` этим способом не подтверждено. На хосте старый Windows 10 build 10240; несовместимость параметра правдоподобна, но точная причина по одному коду не устанавливается.

Одновременно PowerShell запускает команды:

```text
"C:\Windows\system32\cmd.exe" /c move /y C:\Users\Public\Libraries\Passport\3(1).jpg C:\Users\Public\Libraries\Passport\Rez_ZelibRV.pdf
"C:\Windows\system32\cmd.exe" /c C:\Users\Public\Libraries\Passport\Rez_ZelibRV.pdf
```

Это Sysmon 1, #1589–#1590. Команда переименования завершается с 0, Security 4689, #779. Дальнейшее открытие документа поддерживается созданием процессов оболочки и MicrosoftEdge, Security 4688, #782. Содержимое PDF не приложено.

Сочетание `Passport\20.ps1`, `19.jpg`, `conhost --headless`, `3(1).jpg` и `Rez_ZelibRV.pdf` совпадает с цепочкой доставки Merlin в [исследовании Kaspersky](https://securelist.ru/merlin-loki-mythic-attacks/111704/). Поэтому роль PDF как приманки и ожидаемое семейство полезной нагрузки обоснованы CTI, но не анализом самих локальных файлов.

Это попытка T1202 — Indirect Command Execution; T1036 — Masquerading предполагается по исполнению файла с расширением `.jpg`. Реальный PE-файл отсутствует.

### 7. Persistence

В `10:05:02.356` Explorer запускает отдельный CMD PID 2532 с Medium integrity. В `10:05:04.825` и `10:05:13.475` его потомки выполняют `dir` для `AppData\Roaming` и `AppData\Roaming\Microsoft`, Sysmon 1, #1722 и #1724.

В `10:05:30.590` создаётся другая оболочка CMD PID 1876 с High integrity. Родитель — RuntimeBroker PID 3172, Sysmon 1, #1727. Эксплуатация уязвимости или обход UAC не установлены.

В `10:05:33` повышенная оболочка запускает CMD и reg.exe PID 3012:

```text
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v chromeproxy /t REG_SZ /d "$temp\chrome_proxy.exe" /F
```

Sysmon 13, #1730, в `10:05:33.067` подтверждает запись:

```text
HKU\S-1-5-21-934412289-2354128278-1468588150-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\chromeproxy
Details: $temp\chrome_proxy.exe
```

Reg завершается с кодом 0, Security 4689, #837. Однако в значении остаётся буквальный `$temp`: он не раскрыт в путь пользовательского Temp. Создание и исполнение `chrome_proxy.exe` в выгрузке не найдены. Запись автозапуска подтверждена, работающий механизм закрепления — нет.

Это попытка T1547.001 — Registry Run Keys / Startup Folder.

### 8. Credential Access

В `10:05:38.473` повышенный CMD PID 1876 запускает PowerShell PID 2064, Sysmon 1, #1733:

```text
powershell.exe -Command "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding; reg save 'HKLM\SAM' 'sam'"
```

В `10:05:41.363` создаётся reg.exe PID 3528, Sysmon 1, #1735, Security 4688, #842:

```text
"C:\Windows\system32\reg.exe" save HKLM\SAM sam
```

Reg и PowerShell завершаются с кодом 0, Security 4689, #843–#844. Это сильное свидетельство успешного экспорта SAM. Рабочая директория — `C:\Windows\system32\`, поэтому ожидаемый путь относительного результата — `C:\Windows\System32\sam`. Это вычисленный путь: сам файл и событие его создания не предоставлены.

Экспорт SYSTEM, извлечение паролей или пригодных хешей, чтение памяти LSASS и отправка дампа наружу не установлены.

### 9. Discovery

Обычная оболочка CMD PID 2532 продолжает разведывательные команды. В `10:05:55.613` она запускает PowerShell с `dir; ls; whoami /all`, Sysmon 1, #1739. В `10:05:58.190` создаётся `whoami.exe /all`, #1741.

В `10:06:00.750` запускается `systeminfo`, #1742–#1743. WMI-Activity 5858, #1047, в `10:06:00.915606` связывает PID 1620 с запросом `Win32_ComputerSystem` и кодом `0x80041032`. Отдельная WMI-операция завершилась ошибкой/отменой, но сам `systeminfo` позднее завершился с 0, Security 4689, #861. Полный вывод команды не собран.

В `10:06:07.975` выполняется `net users`, Sysmon 1, #1749–#1751, с цепочкой CMD → net.exe → net1.exe. В `10:06:12.313` запускается `whoami /groups`, #1755–#1756. В `10:06:17.037` PowerShell выполняет `ps`, alias Get-Process, #1817.

Команды соответствуют T1083, T1033, T1069.001, T1082, T1087.001 и T1057. Их родительская ветвь начинается от Explorer. Это не доказывает, что команды выдал удалённый оператор: их мог вводить локальный участник учений. Запуск «сметы», архивная цепочка, повышенная оболочка и ветвь разведки не образуют единого дерева потомков вредоносного процесса.

### 10. Просмотр журналов и перезапуск

В `10:06:25` пользователь открывает `eventvwr.msc` через MMC, Sysmon 1, #1853–#1854. Просмотр журналов не равен очистке: Security 1102, System 104 и команды `wevtutil cl` не найдены.

В `10:08:33–10:08:48` наблюдается новый цикл загрузки, System 41, #412, EventLog 6008, #404, и Sysmon 4, #2043. Kernel-Power 41 отражает предыдущую нештатную остановку, но её причина и связь с атакой не установлены. Текст 6008 содержит старое время `13:00:05`, поэтому оно не используется как точный момент сбоя после разведки.

В `10:09:03.693428` зафиксирован интерактивный вход win10user, Security 4624, #1033. Исполнение `chrome_proxy.exe` после входа не наблюдается.

В `10:10:46.327` Explorer создаёт `C:\Users\win10user\Downloads\Logs`, Sysmon 11, #2727. Затем DllHost PID 2108 создаёт 170 событий файлов EVTX в этом каталоге, начиная с #2790 и до последней записи Sysmon #3016 в `10:10:57.765`. Это согласуется с подготовкой набора журналов. Несмотря на большее число имён EVTX в FileCreate, реально в полученном архиве доступны только 20 файлов.

### 11. C2 и Exfiltration

В Sysmon есть 12 событий NetworkConnect, ID 3. Все относятся к компонентам OneDrive. Сетевых соединений от «сметы», PowerShell загрузчика, `19.jpg` или `chrome_proxy.exe` не найдено.

28 DNS-событий, ID 22, содержат системные имена, `wpad`, `oneclient.sfx.ms`, `ecs.office.com` и другие запросы ОС. Отдельный необычный запрос `tuabrpvxmp`, #2086, возникает при загрузке от svchost PID 1052, QueryStatus `9003`, QueryResults `-`. Его назначение не установлено; одного имени без ответа и связи с полезной нагрузкой недостаточно для вывода о DGA/C2.

В WinINet Capture декодированы Payload всех 431 записи. HTTP Host относится к Bing и службам Microsoft: `www.bing.com`, `th.bing.com`, `platform.bing.com`, `self.events.data.microsoft.com`, `login.live.com`, `arc.msn.com`, `login.microsoftonline.com`, `config.teams.microsoft.com`. Base64 в поле Payload — формат телеметрии, а не самостоятельное доказательство обфускации атакующим.

Совпадений с проверенными CTI-назначениями Merlin/Loki не найдено. Успешный C2 и эксфильтрация SAM не подтверждены. WinINet не покрывает все сетевые стеки, а PCAP и сетевых журналов шлюза нет, поэтому отсутствие записи не доказывает невозможность обмена.

### 12. Полезные журналы и фоновая активность

Ключевые источники — `Microsoft-Windows-Sysmon%4Operational.evtx` (3016 записей), `Security.evtx` (1128, включая четыре частично восстановленные) и `System.evtx` (429). Sysmon содержит процессы, хеши, создание файлов, реестр и сеть. Security даёт отсутствующий в Sysmon запуск conhost и коды завершения conhost/reg. System помогает проверить установку Sysmon, версию ОС и перезапуск. Event ID всегда оценивается вместе с провайдером: одинаковый номер в Application и Security не означает одинаковое событие.

`Microsoft-Windows-Bits-Client%4Operational.evtx` (205) полезен для отделения обновления OneDrive. События 59/60, #198–#199, в `10:05:14–10:05:35` показывают успешную загрузку `OneDriveSetup.exe` с `oneclient.sfx.ms`, 82 279 784 байта. Последующие OneDriveSetup, RunOnce и задачи OneDrive согласуются с обновлением; BITS abuse не доказан.

`Microsoft-Windows-WMI-Activity%4Operational.evtx` (1052) полезен точечно для связи с systeminfo. Большинство остальных 5858 — ошибки RSoP/политик. `Microsoft-Windows-GroupPolicy%4Operational.evtx` (285) даёт контекст изменений до доставки. `Microsoft-Windows-Shell-Core%4Operational.evtx` (813) подтверждает установочные ярлыки WinRAR. `Microsoft-Windows-WinINet-Capture%4Analytic.evtx` (431) полезен для проверки HTTP. `Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx` (286) содержит изменения профилей/конфигурации, а не полный журнал сетевых соединений.

В остальных журналах подтверждённой связи с цепочкой нет: `Application.evtx` (322), `Microsoft-Client-Licensing-Platform%4Admin.evtx` (165), `Microsoft-Windows-DeviceSetupManager%4Admin.evtx` (144), `Microsoft-Windows-Kernel-PnP%4Configuration.evtx` (103), `Microsoft-Windows-LiveId%4Operational.evtx` (106), `Microsoft-Windows-PushNotification-Platform%4Operational.evtx` (203), `Microsoft-Windows-SettingSync%4Debug.evtx` (676), `Microsoft-Windows-Store%4Operational.evtx` (1780), `Microsoft-Windows-AppXDeploymentServer%4Operational.evtx` (2142). Это лицензирование, устройства, приложения, уведомления и синхронизация. `Microsoft-Windows-AppReadiness%4Admin.evtx` (152) и `Microsoft-Windows-AppReadiness%4Operational.evtx` (1200) содержат только историческую подготовку 26 августа.

Из 2737 событий FileCreate основная масса — Windows Update: 2180 от svchost, из них 2176 в `SoftwareDistribution\Download`. Компоненты OneDrive создают 191 событие, DllHost — 170 EVTX, `rempl\sedsvc.exe` — 121 событие, «смета» — 46, установка WinRAR — 19, PowerShell — 5, VBoxTray — 2, MMC/WinRAR/Explorer — ещё 3. Массовые записи DLL нельзя целиком приписать ВПО.

PowerShell создаёт временные `qtpa51ne.bp3.ps1` (#1588), `mrekml2a.bb4.ps1` (#1734), `4ykpvqks.usa.ps1` (#1740), `0d34nkli.csm.ps1` (#1819) и CLR UsageLog (#1594). Без содержимого файлов они не объявляются дополнительными загрузчиками.

`sedsvc.exe` запускает w32tm, DismHost и powercfg; другой DismHost является потомком CompatTelRunner. TrustedInstaller записывает штатные Winlogon Notifications. После загрузки создаются системные per-user службы OneSyncSvc, PimIndexMaintenanceSvc, UnistoreSvc и UserDataSvc. Это согласованный фон обслуживания ОС. Sysmon 8, #715, с `KERNELBASE.dll!CtrlRoutine` и удаление системной задачи CEIP через wsqmcons, #729, предшествуют доставке и не связаны с доказанным инжектом или закреплением атакующего.

Названия фильтров Sysmon `Tamper-Winlogon`, `T1060`, `T1122`, `T1053` не являются SIEM-вердиктами. Действия оценивались по процессу, целевому объекту и связям.

Извлечено 14 638 записей. Security #67, #817, #1054 и #1057 восстановлены частично из-за некорректных UTF-16/XML символов. Команда `dir` в #817 подтверждается Sysmon; повреждённое поле родителя не использовалось. Security 1101, #427 и #894, дополнительно указывает потерю событий аудита. Поэтому отсутствие события трактуется как отсутствие подтверждения в выгрузке. PowerShell/Operational с 4104, Defender/Operational, TaskScheduler/Operational, сами образцы и почтовые журналы не приложены.

### 13. Атрибуция группировки

Наиболее обоснованный ответ — Mythic Likho. Редкое сочетание архивной цепочки, Passport, PowerShell, conhost и PDF-приманки поддерживает атрибуцию сценария. Характерные инструменты — Merlin и Loki, включая Loki 2.0; они связаны с фреймворком Mythic. [Исследование Kaspersky от 12 февраля 2025 года](https://securelist.ru/merlin-loki-mythic-attacks/111704/).

Это высокая уверенность в соответствии сценария учений, а не установление личности реального оператора. Исполнение локального Merlin не подтверждено из-за ошибки conhost, а «смета» не совпадает по хешу с опубликованным Loki. C2, lateral movement, эксфильтрация и отключение защиты не включаются в доказанные этапы.

### 14. Sigma-правила

Ответ на вопрос с четырьмя вариантами detection — варианты 1 и 3.

Первый вариант выявляет наблюдаемую CMD-команду поиска архива, Sysmon 1, #1582, Security 4688, #767:

```yaml
detection:
    selection_where:
        Image|endswith: '\cmd.exe'
        CommandLine|contains|all:
            - 'where'
            - '\AppData\Local\Temp'
    condition: selection_where
```

Третий вариант может выявить непрямой запуск внутри скрипта:

```yaml
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'conhost'
            - '--headless'
    condition: selection
```

Для его фактического срабатывания требуется Script Block Logging, обычно PowerShell Event ID 4104. Такого источника в архиве нет: применимость к поведению не равна подтверждённому алерту.

Второй вариант не совпадает с запуском `Passport\20.ps1`: в командной строке PowerShell указан относительный путь без перечисленных Temp-каталогов. Фильтр с `Resume.rar` дополнительно исключал бы строки с этим именем. Четвёртый требует `--headless` и `powershell` в командной строке самого conhost; здесь аргументом является `19.jpg`, а PowerShell — родительский процесс.

При отдельной проверке шести предложенных условий обнаружены: conhost с `--headless` и `.jpg` — Security #776; PowerShell Bypass с Passport — Sysmon #1587 и Security #775; `reg save HKLM\SAM` — Sysmon #1735 и Security #842; Run `chromeproxy` с буквальным `$temp` — Sysmon #1730; создание `Passport\20.ps1` — Sysmon #1586; хеш «сметы» — Sysmon #1380 и #1436. Всего девять совпадений записей, включая дубли одного исполнения между журналами. Это проверка условий по событиям, а не доказательство установленного SIEM или реально сгенерированных алертов.

Корреляция нескольких классов разведки за 90 секунд в дереве CMD PID 2532 также дала бы повод для расследования. Условие требует контекста: аналогичные команды допустимы у администратора и участника учений.

## Цепочка атаки

Перенос «сметы» через VirtualBox → запуск EXE из Temp → распаковка Python-компонентов → завершение EXE.

Отдельная ветвь: Explorer → CMD с поиском Resume.rar → распаковка WinRAR → Passport\20.ps1 → неудачная попытка conhost --headless с 19.jpg → переименование и открытие PDF-приманки.

Параллельные ветви: повышенный CMD → запись Run chromeproxy с буквальным $temp → экспорт SAM с кодом 0; обычный CMD → поиск файлов, пользователей, групп, сведений о системе и процессов.

Единая причинная связь всех ветвей через работающий RAT, успешный C2 и отправка SAM наружу не подтверждены.

## Ответы

| Вопрос | Ответ |
|---|---|
| Какая группировка | Mythic Likho |
| Какое ВПО характерно | Loki |
| Техники исполнения | T1059.003, T1059.001, T1140; T1204.002, T1202,  T1036 |
| Техники разведки | T1083, T1033, T1069.001, T1082, T1087.001, T1057 |
| Подходящие Sigma detection из задания | Варианты 1 и 3; варианту 3 требуется ScriptBlockText/4104 |

