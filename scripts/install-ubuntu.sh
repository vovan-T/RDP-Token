#!/bin/sh
set -eu

install_dir=${RDP_TOKEN_INSTALL_DIR:-/opt/RDP-Token}
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

case "$install_dir" in
    /*) ;;
    *)
        echo "Путь установки должен быть абсолютным: $install_dir" >&2
        exit 1
        ;;
esac
if [ "$install_dir" = "/" ]; then
    echo "Отказ от установки в корень файловой системы." >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Запусти установщик от root: sudo sh scripts/install-ubuntu.sh" >&2
    exit 1
fi
if [ "$(uname -s)" != "Linux" ]; then
    echo "Этот установщик предназначен для Linux." >&2
    exit 1
fi

missing=""
for command_name in docker openssl; do
    if ! command -v "$command_name"; then
        missing="$missing $command_name"
    fi
done
if command -v docker; then
    if ! docker compose version; then
        missing="$missing docker-compose-v2"
    fi
fi
if [ -n "$missing" ]; then
    echo "Не найдены обязательные компоненты:$missing" >&2
    echo "Установи Docker Engine и Compose plugin по официальной инструкции:" >&2
    echo "  https://docs.docker.com/engine/install/ubuntu/" >&2
    echo "После подключения репозитория Docker используются пакеты:" >&2
    echo "  docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin" >&2
    echo "Остальные зависимости Ubuntu:" >&2
    echo "  sudo apt update" >&2
    echo "  sudo apt install openssl ca-certificates vim" >&2
    exit 2
fi

if [ -e "$install_dir" ]; then
    echo "Каталог уже существует: $install_dir" >&2
    echo "Установщик не перезаписывает действующую систему. Используй процедуру обновления из docs/INSTALL.ru.md." >&2
    exit 1
fi

install_parent=$(dirname -- "$install_dir")
install_name=$(basename -- "$install_dir")
stage_dir="$install_parent/.$install_name.install.$$"
install -d -m 0755 "$install_parent"
install -d -m 0755 "$stage_dir"
cleanup() {
    if [ -d "$stage_dir" ]; then
        rm -rf -- "$stage_dir"
    fi
}
trap cleanup EXIT HUP INT TERM

for file_name in Dockerfile README.md SECURITY.md CHANGELOG.md requirements.txt docker-compose.yml recovery; do
    cp -a "$source_dir/$file_name" "$stage_dir/$file_name"
done
cp -a "$source_dir/.env.example" "$stage_dir/.env.example"
for directory_name in app certs docs nginx scripts tests; do
    cp -a "$source_dir/$directory_name" "$stage_dir/$directory_name"
done

find "$stage_dir" -type d -name __pycache__ -prune -exec rm -rf -- {} +
find "$stage_dir" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

sh "$stage_dir/scripts/create-env.sh" "$stage_dir/.env"
sh "$stage_dir/scripts/prepare-data.sh"
mv -- "$stage_dir" "$install_dir"
trap - EXIT HUP INT TERM

echo "RDP-Token установлен в $install_dir"
echo "Дальше:"
echo "  1. vim $install_dir/.env"
echo "  2. добавь клиентский CA и CRL по инструкции $install_dir/certs/README.md"
echo "  3. cd $install_dir"
echo "  4. sudo docker compose config --quiet"
echo "  5. sudo docker compose up -d --build"
