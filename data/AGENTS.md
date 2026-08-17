# data/ — before you put anything here

Empty by design. See [`README.md`](README.md) for why.

If you are about to add a file, check which of these it actually is:

- **A generated value.** It belongs in `output/data/`, written by a script and
  regenerated on every run. Never committed, never hand-maintained.
- **Evidence backing a claim.** It belongs in [`../output/`](../output/AGENTS.md),
  produced by a `run.sh` stage and committed alongside the code that produces it.
- **A test fixture.** It belongs in the test that uses it, built in `tmp_path`. This
  suite constructs real files rather than shipping them, so a fixture cannot silently
  go stale against the code it exercises.
- **A genuine external input.** Then it goes here — and it needs provenance recorded
  in this file: where it came from, its digest, its licence, and which claim depends on
  it. An undocumented data file is an unverifiable result.

Nothing secret, ever. No keys, no shares, no recovered plaintext. `.gitignore` already
excludes `*.hex` and `keys/`, and `src/secure_io.py` exists so those files are created
owner-only wherever they land — but the first rule is that they do not land in the
repository at all.
