# Coverage improvement contract

Requested target: **95% statement coverage of the whole `vulnassess` package**.

Baseline on 9 October 2026: 731 tests and 510 subtests passed; 86.33%
statement coverage (9,779 statements, 1,337 missing).

- Keep the existing package scope. Do not omit modules, add coverage exclusions,
  skip failing tests, or remove safety checks to improve the percentage.
- Assert observable outcomes, including malformed input, outages and persistence
  failures. Mock external transports, not the business behavior being tested.
- Tests use synthetic credentials and temporary data. They must not scan targets,
  call paid providers, or read workstation credentials.
- Preserve deterministic authorization and scoring, immutable evidence and
  fail-closed AI validation.
- Enforce the 95% floor in CI, Makefile and scripts/check.py. The complete local
  suite demonstrated 95.17% on 10 October 2026 before the floor was raised.
  A remote CI result is still required before merge.
- Report statement coverage separately from branch coverage, test pass counts,
  real-service integration and model accuracy. They are not interchangeable.

Verification commands:

```text
python -m pytest --cov=vulnassess --cov-fail-under=95
python -m ruff check .
python -m ruff format --check .
python -m pyright
```

On this workstation only, add `-p no:hypothesispytest` because Windows App
Control blocks an unrelated installed plugin. This does not disable project tests.
