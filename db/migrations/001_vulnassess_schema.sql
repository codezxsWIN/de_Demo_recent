-- VulnAssess assessment store for Supabase PostgreSQL.
-- This schema is deliberately private to the backend; the browser only sees
-- the project's existing read-only /api routes.

begin;

create schema if not exists vulnassess;
revoke all on schema vulnassess from public;

create table if not exists vulnassess.runs (
    run_id text primary key,
    started_at timestamptz not null,
    config_hash text not null,
    summary_json jsonb not null default '{}'::jsonb
);

create table if not exists vulnassess.hosts (
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    ip inet not null,
    json jsonb not null,
    primary key (run_id, ip)
);

create table if not exists vulnassess.findings (
    id text primary key,
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    host_ip inet not null,
    tool text not null,
    json jsonb not null,
    first_seen timestamptz not null,
    last_seen timestamptz not null
);
create index if not exists findings_run_idx on vulnassess.findings (run_id);

create table if not exists vulnassess.finding_runs (
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    finding_id text not null references vulnassess.findings (id) on delete cascade,
    seen_at timestamptz not null,
    primary key (run_id, finding_id)
);
create index if not exists finding_runs_finding_idx on vulnassess.finding_runs (finding_id);

create table if not exists vulnassess.cve (
    id text primary key,
    json jsonb not null,
    cvss31_base double precision,
    cvss40_base double precision
);

create table if not exists vulnassess.enrichments (
    finding_id text not null references vulnassess.findings (id) on delete cascade,
    cve_id text not null references vulnassess.cve (id),
    json jsonb not null,
    primary key (finding_id, cve_id)
);

create table if not exists vulnassess.epss (
    cve text primary key references vulnassess.cve (id),
    epss double precision,
    percentile double precision,
    score_date date
);

create table if not exists vulnassess.kev (
    cve text primary key references vulnassess.cve (id),
    json jsonb not null
);

create table if not exists vulnassess.feeds_meta (
    feed text primary key,
    path text not null,
    sha256 text not null,
    file_date date,
    rows integer not null,
    loaded_at timestamptz not null
);

create table if not exists vulnassess.context_profiles (
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    host_ip inet not null,
    json jsonb not null,
    primary key (run_id, host_ip)
);

create table if not exists vulnassess.scores (
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    finding_id text not null references vulnassess.findings (id) on delete cascade,
    json jsonb not null,
    risk double precision not null,
    band text not null,
    primary key (run_id, finding_id)
);
create index if not exists scores_risk_idx on vulnassess.scores (run_id, risk desc);

create table if not exists vulnassess.rationales (
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    finding_id text not null references vulnassess.findings (id) on delete cascade,
    json jsonb not null,
    primary key (run_id, finding_id)
);

commit;
