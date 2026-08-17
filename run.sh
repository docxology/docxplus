#!/usr/bin/env bash
# docxplus pipeline driver. Deterministic, dependency-light.
#
#   ./run.sh                  # the whole pipeline, in dependency order
#   ./run.sh test             # test suite with the coverage gate
#   ./run.sh build            # build + verify the example document only
#   ./run.sh render           # tokens, figures, and the manuscript PDF
#   ./run.sh figure           # the capacity figure alone (needs matplotlib)
#   ./run.sh roundtrip        # synthetic and real-project round trips
#   ./run.sh dossier          # the evidence dossier document
#   ./run.sh living           # the self-describing manuscript .docx
#   ./run.sh preflight        # environment and capability check
#
# `all` renders the manuscript deliberately. The render is the only stage that
# runs the pandoc diagnostic gate, and pandoc reports an unresolved cross-reference
# and then exits 0 — so leaving the render out of the default pipeline meant a
# broken reference could ship into the committed PDF with every other stage green.
set -euo pipefail
cd "$(dirname "$0")"

PY=".venv/bin/python"
if [[ ! -x "${PY}" ]]; then
  echo "[setup] creating venv"; uv venv >/dev/null; PY=".venv/bin/python"
  uv pip install -e '.[dev,media]' >/dev/null
fi

run_preflight() { "${PY}" scripts/00_preflight.py; }
run_tests()     { "${PY}" -m pytest --cov=src --cov-report=term-missing -q; }
run_build()     { "${PY}" scripts/01_build_example.py; "${PY}" scripts/02_roundtrip_report.py; }
run_figure()    { "${PY}" scripts/03_capacity_figure.py; }
run_dossier()   { "${PY}" scripts/04_dossier.py; }
run_roundtrip() { "${PY}" scripts/06_project_roundtrip.py; "${PY}" scripts/07_template_roundtrip.py; }
run_living()    { "${PY}" scripts/05_living_manuscript.py; }
run_render()    { "${PY}" scripts/z_generate_manuscript_variables.py && "${PY}" scripts/render_manuscript.py; }

usage() {
  cat <<'EOF'
usage: ./run.sh [stage]

  all         every stage below, in dependency order (default)
  preflight   environment and capability check
  test        test suite with the coverage gate
  build       example document, built and verified
  roundtrip   synthetic and real-project round trips, all four formats
  dossier     evidence dossier document
  render      manuscript tokens, figures, and PDF (runs the diagnostic gate)
  living      self-describing manuscript .docx
  figure      capacity figure alone
EOF
}

case "${1:-all}" in
  preflight) run_preflight ;;
  test)      run_tests ;;
  build)     run_build ;;
  figure)    run_figure ;;
  dossier)   run_dossier ;;
  roundtrip) run_roundtrip ;;
  living)    run_living ;;
  # `manuscript-render` and `manuscript` are the pre-1.0 verb names, kept so
  # existing invocations and docs do not break.
  render|manuscript-render) run_render ;;
  manuscript) run_living ;;
  all)
    run_preflight
    run_tests
    run_build
    run_dossier
    run_roundtrip
    run_render
    run_living
    ;;
  -h|--help|help) usage ;;
  *) usage; exit 2 ;;
esac
