# Set up and verify docxplus

Use Git and uv. Run the following commands from this repository's root.
The verification below uses Python 3.14 and the committed lockfile.

```sh
uv sync --locked --all-extras --python 3.14
uv run --no-sync --python 3.14 docxplus --help
```

The development extra supplies the test and lint tools, the media extra supplies
Pillow, and the figures extra supplies matplotlib. Install all extras when
rebuilding the manuscript plates.

## Inspect a delivered example

```sh
uv run --no-sync --python 3.14 docxplus inspect output/documents/example_docxplus.docx
```

Inspection describes the stored package. See the [CLI reference](cli.md) for
the document creation, extraction, validation, and verification commands and
what their results establish. Authenticity requires the expected signing key.

## Check the documentation and manuscript

```sh
uv run --no-sync --python 3.14 pytest tests/test_docs.py tests/test_numbering.py tests/test_manuscript_render.py tests/test_manuscript_vars.py tests/test_project_paths.py
```

The [manuscript pipeline](manuscript-pipeline.md) explains native typesetting
and the pinned Template check. These local checks exercise navigation,
configuration, and rendering. The [release evidence requirements](manuscript/MANUSCRIPT_STATUS.md)
cover separate qualification of Office consumers, runtime confinement, and
regenerated artifacts.
