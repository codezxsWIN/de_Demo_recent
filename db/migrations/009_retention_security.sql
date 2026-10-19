-- 009 Retention policy support and a blanket security pass over every table
-- in the private schema. Idempotent: safe to re-run after adding tables.

begin;

create table if not exists vulnassess.retention_policies (
    table_name text primary key,
    retention_days integer not null check (retention_days > 0),
    basis text not null,
    updated_at timestamptz not null default now()
);
comment on table vulnassess.retention_policies is
    'Documented retention window per sensitive table. A backend cleanup job '
    'reads this table to expire old assessment evidence; nothing is deleted '
    'silently.';

-- Evidence-bearing tables keep a retention-relevant timestamp; the cleanup
-- job uses each table's own timestamp column (observed_at, captured_at,
-- decided_at, created_at) plus the policy above.

create table if not exists vulnassess.schema_migrations (
    version text primary key,
    sha256 text not null,
    applied_at timestamptz not null default now()
);

-- Blanket defence in depth: enable and force RLS on every table in the
-- private schema and revoke all access from the browser-facing roles,
-- regardless of which migration created the table.
do $$
declare
    target record;
begin
    for target in
        select tablename from pg_tables where schemaname = 'vulnassess'
    loop
        execute format('alter table vulnassess.%I enable row level security', target.tablename);
        execute format('alter table vulnassess.%I force row level security', target.tablename);
    end loop;
end $$;

revoke all on all tables in schema vulnassess from anon, authenticated;
revoke all on all sequences in schema vulnassess from anon, authenticated;
revoke all on all functions in schema vulnassess from anon, authenticated;

alter table vulnassess.retention_policies enable row level security;
alter table vulnassess.retention_policies force row level security;
alter table vulnassess.schema_migrations enable row level security;
alter table vulnassess.schema_migrations force row level security;

commit;
