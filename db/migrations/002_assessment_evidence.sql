-- Expanded, run-scoped evidence model for authorised assessments.
-- These tables are private to the backend and retain evidence without exposing it
-- to the browser or a public Data API.

begin;

create table if not exists vulnassess.assessment_targets (
    id uuid primary key default gen_random_uuid(),
    label text not null,
    scope_ref text not null,
    target_kind text not null check (target_kind in ('domain', 'ip', 'cidr', 'application')),
    target_value text not null,
    authorization_ref text not null,
    created_at timestamptz not null default now(),
    unique (scope_ref, target_kind, target_value)
);

create table if not exists vulnassess.assets (
    id uuid primary key default gen_random_uuid(),
    target_id uuid not null references vulnassess.assessment_targets (id) on delete cascade,
    run_id text references vulnassess.runs (run_id) on delete set null,
    address inet,
    hostname text,
    asset_role text,
    criticality text check (criticality in ('low', 'medium', 'high', 'critical')),
    owner_note text,
    tags jsonb not null default '[]'::jsonb,
    observed_at timestamptz not null default now(),
    unique nulls not distinct (target_id, run_id, address, hostname)
);

create table if not exists vulnassess.services (
    id uuid primary key default gen_random_uuid(),
    asset_id uuid not null references vulnassess.assets (id) on delete cascade,
    port integer not null check (port between 1 and 65535),
    transport text not null check (transport in ('tcp', 'udp')),
    name text,
    product text,
    version text,
    cpe text,
    tls boolean not null default false,
    observed_at timestamptz not null default now(),
    unique (asset_id, port, transport)
);

create table if not exists vulnassess.scan_jobs (
    id uuid primary key default gen_random_uuid(),
    target_id uuid not null references vulnassess.assessment_targets (id) on delete restrict,
    run_id text references vulnassess.runs (run_id) on delete set null,
    tool text not null,
    status text not null check (status in ('planned', 'running', 'completed', 'failed', 'cancelled')),
    requested_at timestamptz not null default now(),
    started_at timestamptz,
    completed_at timestamptz,
    scope_snapshot jsonb not null,
    command_summary text not null,
    result_summary jsonb not null default '{}'::jsonb
);

create table if not exists vulnassess.scan_evidence (
    id uuid primary key default gen_random_uuid(),
    scan_job_id uuid not null references vulnassess.scan_jobs (id) on delete cascade,
    finding_id text references vulnassess.findings (id) on delete set null,
    evidence_type text not null,
    excerpt text not null,
    source_sha256 text not null,
    captured_at timestamptz not null default now(),
    provenance jsonb not null default '{}'::jsonb
);

create table if not exists vulnassess.model_evaluations (
    id uuid primary key default gen_random_uuid(),
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    model_name text not null,
    model_hash text,
    task text not null,
    metrics jsonb not null,
    dataset_ref text not null,
    evaluated_at timestamptz not null default now()
);

create table if not exists vulnassess.audit_events (
    id bigint generated always as identity primary key,
    run_id text references vulnassess.runs (run_id) on delete set null,
    event_type text not null,
    actor text not null,
    detail jsonb not null default '{}'::jsonb,
    occurred_at timestamptz not null default now()
);

create index if not exists assets_target_idx on vulnassess.assets (target_id, observed_at desc);
create index if not exists scan_jobs_target_idx on vulnassess.scan_jobs (target_id, requested_at desc);
create index if not exists scan_evidence_finding_idx on vulnassess.scan_evidence (finding_id);
create index if not exists audit_events_run_idx on vulnassess.audit_events (run_id, occurred_at desc);

commit;
