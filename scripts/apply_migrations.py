"""Apply db/migrations/*.sql to a Supabase/PostgreSQL backend.

Usage:
    VULNASS_DATABASE_URL=postgresql://... python scripts/apply_migrations.py [--check]

Reads the connection URL from the backend-only environment variable
VULNASS_DATABASE_URL (never from a committed file). Each migration runs in its
own transaction and is recorded in vulnassess.schema_migrations with its
SHA-256; already-applied migrations are skipped, so the runner is idempotent.
--check prints what would run without touching the database.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "db" / "migrations"
ENV_VAR = "VULNASS_DATABASE_URL"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="list pending migrations without applying them"
    )
    arguments = parser.parse_args()

    url = os.environ.get(ENV_VAR, "")
    if not url.startswith(("postgresql://", "postgres://")):
        print(f"MISSING: set {ENV_VAR} to a PostgreSQL URL (Supabase session URI)")
        return 2
    try:
        import psycopg
    except ImportError:
        print("MISSING: install psycopg first (pip install 'psycopg[binary]>=3.2')")
        return 2

    files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    if not files:
        print(f"MISSING: no migrations found in {MIGRATIONS_DIR}")
        return 2

    with psycopg.connect(url) as connection:
        with connection.cursor() as cursor:
            cursor.execute("create schema if not exists vulnassess")
            cursor.execute(
                "create table if not exists vulnassess.schema_migrations ("
                "version text primary key, sha256 text not null, "
                "applied_at timestamptz not null default now())"
            )
            cursor.execute("select version, sha256 from vulnassess.schema_migrations")
            applied = dict(cursor.fetchall())
        pending = []
        for path in files:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if applied.get(path.name) == digest:
                continue
            pending.append((path, digest))

        if not pending:
            print("schema is up to date")
            return 0
        for path, digest in pending:
            print(("would apply" if arguments.check else "applying") + f" {path.name}")
            if arguments.check:
                continue
            sql = path.read_text(encoding="utf-8")
            with connection.cursor() as cursor:
                cursor.execute(sql)
                cursor.execute(
                    "insert into vulnassess.schema_migrations (version, sha256) "
                    "values (%s, %s) on conflict (version) do update set "
                    "sha256 = excluded.sha256",
                    (path.name, digest),
                )
            connection.commit()
            print(f"applied {path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
