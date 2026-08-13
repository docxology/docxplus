# scripts/ — thin orchestrators

Scripts coordinate I/O, run the domain modules in `src/`, and print output paths to
stdout. They contain NO business logic. Numbered by pipeline order:

- `00_preflight.py` — report available capabilities (never masks absence as pass)
- `01_build_example.py` — build the demonstration DOCX+ into output/documents/
- `02_roundtrip_report.py` — re-read, verify, emit output/reports/roundtrip.json
- `03_capacity_figure.py` — optional per-channel capacity figure (matplotlib)
