#!/usr/bin/env bash
set -euo pipefail

VENV_PATH="${VENV_PATH:-/workspace/.venv}"

if [[ ! -d "${VENV_PATH}" ]]; then
  python3.13 -m venv "${VENV_PATH}"
fi

# shellcheck disable=SC1090
source "${VENV_PATH}/bin/activate"

python -m pip install --upgrade pip
python -m pip install --upgrade awscli

aws --version
