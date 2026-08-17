# .github/ — changing CI

One workflow: [`workflows/ci.yml`](workflows/ci.yml). The gates and what they do not
cover are in [`README.md`](README.md).

## Rules

- **A gate may only get stricter.** Lowering the coverage floor, dropping the lint
  step, or adding `continue-on-error` to a failing job converts a real signal into a
  green badge. If a gate is wrong, fix the code or delete the gate deliberately with a
  reason in the commit — never soften it in place.
- **Keep the local and CI commands identical.** The four gates in `README.md` are the
  same commands a contributor runs by hand. When they diverge, CI stops predicting what
  happens on a machine, and the divergence is discovered at the worst moment.
- **Install all three extras.** `.[dev,media,figures]`. Without `figures`,
  `build_figures.py` exits 0 and the render silently reuses committed plates.
- **Never add a step that writes to the repository.** No auto-commit, no auto-format,
  no regenerating `output/` in CI. The committed artefacts are evidence produced by a
  human-run pipeline; a bot regenerating them removes the thing that makes them
  evidence.
- **No secrets.** Nothing here needs credentials. A workflow that gains a secret gains
  a threat model, and this repository's threat model is documented in
  `docs/security-model.md`, not in a CI config.

## If you add a job

Add it to the table in [`README.md`](README.md) in failure order, and state plainly in
the "what CI does not cover" section anything it still leaves unchecked. A gate that
readers believe covers more than it does is worse than no gate.
