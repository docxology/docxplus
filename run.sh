#!/usr/bin/env bash
# DOCX+ pipeline driver. Deterministic, dependency-light.
#
#   ./run.sh              # preflight -> tests -> build example -> roundtrip report
#   ./run.sh test         # test suite with coverage gate
#   ./run.sh build        # build + verify the example document only
#   ./run.sh figure       # optional capacity figure (needs matplotlib)
set -euo pipefail
cd "$(dirname "$0")"

PY=".venv/bin/python"
if [[ ! -x "${PY}" ]]; then
  echo "[setup] creating venv"; uv venv >/dev/null; PY=".venv/bin/python"
  uv pip install -e '.[dev,media]' >/dev/null
fi

run_tests()   { "${PY}" -m pytest --cov=src --cov-report=term-missing -q; }
run_build()   { "${PY}" scripts/01_build_example.py; "${PY}" scripts/02_roundtrip_report.py; }
run_figure()  { "${PY}" scripts/03_capacity_figure.py; }
run_dossier() { "${PY}" scripts/04_dossier.py; }
run_preflight() { "${PY}" scripts/00_preflight.py; }

case "${1:-all}" in
  test)   run_tests ;;
  build)  run_build ;;
  figure) run_figure ;;
  dossier) run_dossier ;;
  preflight) run_preflight ;;
  all)
    run_preflight
    run_tests
    run_build
    run_dossier
    ;;
  *) echo "usage: $0 [all|test|build|dossier|figure|preflight]"; exit 2 ;;
esac
