#!/bin/sh
set -eu
OLAX_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ "${1:-}" = setup ]; then
    shift
    if command -v python3.12 >/dev/null 2>&1; then OLAX_DEFAULT_PYTHON=python3.12; else OLAX_DEFAULT_PYTHON=python3; fi
    exec "${OLAX_PYTHON:-$OLAX_DEFAULT_PYTHON}" "$OLAX_ROOT/setup.py" "$@"
fi
if [ ! -x "$OLAX_ROOT/.venv/bin/python" ]; then
    echo 'Сначала выполните ./olax.sh setup' >&2
    exit 1
fi
exec "$OLAX_ROOT/.venv/bin/python" "$OLAX_ROOT/olax.py" "$@"
