# SYNTHETIC test data — not evidence

Everything in this directory is invented for unit tests of pure logic. None of it was
produced by a scanner, a feed or a model, and none of it may be cited as evidence that a
parser, feed loader or score works against real data.

- CVE ids use the reserved-looking `CVE-1999-90xx` range so they can never collide with a
  real advisory.
- Hosts are the three lab addresses in `config/scope.yaml` plus one deliberately-down host.
- The three feed files under `feeds/` mimic the shape of NVD API 2.0, the EPSS daily CSV and
  the CISA KEV catalog. They contain two CVEs, two EPSS rows and one KEV row.
- `synthetic_role_train.jsonl` and `synthetic_role_validation.jsonl` contain 54 training and
  18 independent validation groups across nine role classes. They exercise model training and
  calibration only; their perfect separability is not evidence of real-world accuracy.

Real captures belong in `tests/fixtures/{nmap,zap,intel}/` with the capture README filled in
by the human who ran the tool.
