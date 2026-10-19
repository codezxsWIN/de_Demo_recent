"""Refuse dependency provisioning: installation is not run by the agent."""

import sys


def main() -> int:
    """Fail closed until a human-approved provisioning process is established."""
    print(
        "Dependency installation is disabled: not run by the agent. "
        "A human must review and provision pinned, hash-verified dependencies. "
        "See docs/security.md.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
