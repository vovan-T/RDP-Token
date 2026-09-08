# Что установить для RDP-Token

RDP-Token состоит из трёх независимых частей: Ubuntu-сервера, браузера обычного
пользователя и настольного `RDP-Token Manager` для администратора. Устанавливать
Manager на Ubuntu-сервер и подключать USB-токен к Docker не требуется.

## 1. Ubuntu-сервер

Нужно заранее установить:

- Docker Engine;
- Docker Compose v2, команда должна выглядеть как `docker compose`;
- OpenSSL;
- системные корневые сертификаты `ca-certificates`;
- `vim` — только для ручного редактирования `.env`.

Проверка:

```sh
docker --version
docker compose version
openssl version
```

Рекомендуемый вариант — официальный Docker Engine и Compose plugin по
[инструкции Docker для Ubuntu](https://docs.docker.com/engine/install/ubuntu/).
После подключения официального репозитория Docker устанавливаются пакеты:

```sh
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo apt install openssl ca-certificates vim
```

Если Docker уже установлен из репозитория самой Ubuntu, не смешивай его пакеты
с `docker-ce`. Достаточно проверить, что работают `docker` и `docker compose`.
Установщик RDP-Token не меняет источник пакетов и не переустанавливает Docker.

Установка приложения из релизного архива:

```sh
tar -xzf RDP-Token-Ubuntu-0.7.0.tar.gz
cd RDP-Token-Ubuntu-0.7.0
sudo sh scripts/install-ubuntu.sh
```

Результат:

```text
/opt/RDP-Token/
├── .env                 закрытые настройки и случайный секрет
├── app/                 WEB и RDP-прокси
├── certs/               публичный клиентский CA и CRL
├── data/                SQLite, загруженные CA/CRL и резервные копии
├── nginx/               HTTPS и проверка клиентского сертификата
└── docker-compose.yml
```

Перед первым запуском:

```sh
sudo vim /opt/RDP-Token/.env
sudo vim /opt/RDP-Token/certs/README.md
cd /opt/RDP-Token
sudo docker compose config --quiet
sudo docker compose up -d --build
sudo docker compose ps
```

В `.env` обязательно задаются DNS-имя шлюза, пути к серверному TLS-сертификату и
ключу, серийный номер сертификата первого администратора и внешний адрес RDP.
Закрытый ключ клиентского CA на RDP-Token не копируется.

## 2. Сетевые порты

| Назначение | По умолчанию | Доступ |
|---|---:|---|
| HTTPS-портал | TCP 18443 либо внешний TCP 443 | пользователи |
| Flask backend | TCP 18081 | только `127.0.0.1` |
| RDP-шлюзы | TCP 60000–60999 | только разрешённые внешние сети |
| RDP к рабочим местам | обычно TCP 3389 | Ubuntu-сервер → внутренние системы |

Диапазон RDP меняется в `.env`, а после инициализации — в панели управления.
NAT и firewall установщик не настраивает.

## 3. Обычный пользователь через браузер

На его компьютере не нужен `RDP-Token Manager`. Нужны:

- браузер, умеющий выбирать клиентский сертификат;
- драйвер или PKCS#11/CSP/KSP-провайдер конкретного USB-токена;
- стандартный RDP-клиент (`mstsc.exe` в Windows или совместимый клиент Linux).

Для Rutoken используй только официальный
[центр загрузки Windows](https://www.rutoken.ru/support/download/windows/) или
[пакеты для Linux](https://www.rutoken.ru/support/download/nix/). Для ESMART —
[официальный ESMART PKI Client](https://token.esmart.ru/downloads).

На Debian/Ubuntu/Astra базовый PC/SC-слой обычно устанавливается так:

```sh
sudo apt update
sudo apt install pcscd pcsc-tools libccid libpcsclite1 opensc
sudo systemctl enable --now pcscd.socket
pcsc_scan
```

По требованиям Rutoken для deb-систем необходимы `libccid` не ниже 1.4.2,
`pcscd` и `libpcsclite1`. Для ESMART или отдельных моделей Rutoken дополнительно
установи их официальный PKCS#11-модуль. В Firefox Linux модуль добавляется в
«Настройки → Приватность и защита → Устройства защиты». Само обнаружение токена
в `pcsc_scan` ещё не означает, что браузер видит сертификат и закрытый ключ.

## 4. RDP-Token Manager для Windows

Для готового EXE Python и Java не нужны. Распаковывается весь каталог:

```text
RDP-Token-Manager/
├── RDP-Token-Manager.exe
└── lib/
    ├── rtadmin.exe
    ├── rtpkcs11ecp.dll
    ├── PKIClientCli.exe
    ├── isbc_pkcs11_main.dll
    └── остальные зависимости производителя
```

EXE нельзя переносить отдельно от `lib`. Дополнительно в Windows должен быть
установлен официальный драйвер/провайдер токена. Публичный GitHub Release не
включает сторонние файлы `lib`: их нужно получить у производителя и положить в
`lib` рядом с EXE. Локальный лабораторный комплект с разрешёнными владельцем
копиями собирается отдельно.

Адрес сервера задаётся кнопкой с шестерёнкой. Настройки хранятся в
`%APPDATA%\RDP-Token\client.json`; PIN и закрытые ключи туда не записываются.

## 5. Запуск Manager из исходников

Нужны Python 3.12 или 3.14 с Tkinter и зависимости проекта:

```powershell
python -m pip install -r token-admin\requirements.txt
python token-admin\token_admin.py
```

Для сборки EXE дополнительно нужен PyInstaller:

```powershell
python -m pip install pyinstaller
powershell -ExecutionPolicy Bypass -File token-admin\build-windows.ps1 -Python python
```

Установка Python/PyInstaller нужна только разработчику и не требуется обычному
пользователю готового EXE.

## 6. Что не устанавливается автоматически

- Docker и системные пакеты;
- драйверы Rutoken/ESMART;
- сертификаты и закрытые ключи;
- правила NAT/firewall и проброс портов;
- доверие к серверному TLS-сертификату;
- обновление CRL внешнего CA.

Это сделано намеренно: установщик не должен менять сетевую безопасность и
пакетную базу Ubuntu без отдельного решения администратора.
