-- 004 Asset inventory: richer asset records, append-only service observation
-- history, and evidence-backed relationships between assets.

begin;

alter table vulnassess.assets
    add column if not exists mac macaddr;
alter table vulnassess.assets
    add column if not exists os_guess text;
alter table vulnassess.assets
    add column if not exists environment text
        check (environment in ('prod', 'test', 'dev'));
alter table vulnassess.assets
    add column if not exists source_scan_id uuid
        references vulnassess.scan_jobs (id) on delete set null;

-- Append-only service history: `services` keeps the current view, this table
-- keeps every observation so changes can be compared between runs.
create table if not exists vulnassess.service_observations (
    id uuid primary key default gen_random_uuid(),
    asset_id uuid not null references vulnassess.assets (id) on delete cascade,
    scan_job_id uuid references vulnassess.scan_jobs (id) on delete set null,
    port integer not null check (port between 1 and 65535),
    transport text not null check (transport in ('tcp', 'udp')),
    name text,
    product text,
    version text,
    cpe text,
    tls boolean not null default false,
    banner text,
    state text not null default 'open'
        check (state in ('open', 'closed', 'filtered')),
    evidence_source text not null,
    observed_at timestamptz not null default now(),
    constraint service_observations_unique
        unique (asset_id, port, transport, observed_at)
);
comment on table vulnassess.service_observations is
    'Historical per-run service observations; rows are never updated so two '
    'runs can be diffed to show what changed on a host.';

create index if not exists service_observations_asset_idx
    on vulnassess.service_observations (asset_id, port, transport, observed_at desc);
create index if not exists service_observations_scan_idx
    on vulnassess.service_observations (scan_job_id);

create table if not exists vulnassess.asset_relationships (
    id uuid primary key default gen_random_uuid(),
    from_asset uuid not null references vulnassess.assets (id) on delete cascade,
    to_asset uuid not null references vulnassess.assets (id) on delete cascade,
    relation text not null
        check (relation in ('hosts', 'connects_to', 'depends_on', 'backed_by')),
    evidence jsonb not null default '{}'::jsonb,
    scan_job_id uuid references vulnassess.scan_jobs (id) on delete set null,
    created_at timestamptz not null default now(),
    constraint asset_relationships_unique unique (from_asset, to_asset, relation),
    constraint asset_relationships_no_self check (from_asset <> to_asset)
);
comment on table vulnassess.asset_relationships is
    'Evidence-supported links between assets, e.g. internet-facing app -> '
    'database -> domain controller.';

create index if not exists asset_relationships_from_idx
    on vulnassess.asset_relationships (from_asset);
create index if not exists asset_relationships_to_idx
    on vulnassess.asset_relationships (to_asset);

alter table vulnassess.service_observations enable row level security;
alter table vulnassess.service_observations force row level security;
revoke all on vulnassess.service_observations from anon, authenticated;

alter table vulnassess.asset_relationships enable row level security;
alter table vulnassess.asset_relationships force row level security;
revoke all on vulnassess.asset_relationships from anon, authenticated;

commit;
