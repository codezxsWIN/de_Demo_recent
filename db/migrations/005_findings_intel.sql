-- 005 Findings lifecycle and vulnerability intelligence: canonical columns on
-- findings, multi-source mapping tables, and a curated intel table with feed
-- provenance and freshness.

begin;

alter table vulnassess.findings
    add column if not exists asset_id uuid
        references vulnassess.assets (id) on delete set null;
alter table vulnassess.findings
    add column if not exists title text;
alter table vulnassess.findings
    add column if not exists description text;
alter table vulnassess.findings
    add column if not exists severity text
        check (severity in ('critical', 'high', 'medium', 'low', 'info'));
alter table vulnassess.findings
    add column if not exists confidence real check (confidence between 0 and 1);
alter table vulnassess.findings
    add column if not exists port integer check (port between 1 and 65535);
alter table vulnassess.findings
    add column if not exists url text;
alter table vulnassess.findings
    add column if not exists lifecycle_status text not null default 'open'
        check (lifecycle_status in ('open', 'resolved'));
alter table vulnassess.findings
    add column if not exists resolved_at timestamptz;
alter table vulnassess.findings
    add column if not exists recurrence_count integer not null default 0;
alter table vulnassess.findings
    add column if not exists scan_job_id uuid
        references vulnassess.scan_jobs (id) on delete set null;

create index if not exists findings_lifecycle_idx
    on vulnassess.findings (lifecycle_status, severity, last_seen desc);
create index if not exists findings_asset_idx on vulnassess.findings (asset_id);

-- One finding can be supported by several tools and map to several CVEs/CWEs.
create table if not exists vulnassess.finding_cves (
    finding_id text not null references vulnassess.findings (id) on delete cascade,
    cve_id text not null references vulnassess.cve (id) on delete restrict,
    source_tool text not null,
    confidence real check (confidence between 0 and 1),
    created_at timestamptz not null default now(),
    primary key (finding_id, cve_id)
);

create table if not exists vulnassess.finding_cwes (
    finding_id text not null references vulnassess.findings (id) on delete cascade,
    cwe_id text not null,
    source text not null default 'scanner',
    created_at timestamptz not null default now(),
    primary key (finding_id, cwe_id),
    check (cwe_id like 'CWE-%')
);

create table if not exists vulnassess.finding_assets (
    finding_id text not null references vulnassess.findings (id) on delete cascade,
    asset_id uuid not null references vulnassess.assets (id) on delete cascade,
    created_at timestamptz not null default now(),
    primary key (finding_id, asset_id)
);

-- Curated per-CVE intelligence with provenance and freshness. Never marks a
-- finding confirmed: confirmation only comes from scanner evidence or a human
-- review decision (see 007_review_workflow.sql).
create table if not exists vulnassess.vuln_intel (
    cve_id text primary key references vulnassess.cve (id) on delete cascade,
    cvss31_vector text,
    cvss31_base real check (cvss31_base between 0 and 10),
    cvss40_vector text,
    cvss40_base real check (cvss40_base between 0 and 10),
    epss_score real check (epss_score between 0 and 1),
    epss_percentile real check (epss_percentile between 0 and 100),
    epss_date date,
    in_kev boolean not null default false,
    kev_date_added date,
    exploit_maturity text not null default 'none'
        check (exploit_maturity in ('none', 'poc', 'functional', 'weaponized')),
    patch_references jsonb not null default '[]'::jsonb,
    remediation_guidance text,
    feed_source text not null,
    feed_date date,
    fetched_at timestamptz not null default now()
);
comment on table vulnassess.vuln_intel is
    'Enrichment facts per CVE with the feed they came from and when it was '
    'published, so stale intelligence is detectable at query time.';

create index if not exists finding_cves_cve_idx on vulnassess.finding_cves (cve_id);
create index if not exists vuln_intel_kev_idx on vulnassess.vuln_intel (in_kev)
    where in_kev;

alter table vulnassess.finding_cves enable row level security;
alter table vulnassess.finding_cves force row level security;
revoke all on vulnassess.finding_cves from anon, authenticated;

alter table vulnassess.finding_cwes enable row level security;
alter table vulnassess.finding_cwes force row level security;
revoke all on vulnassess.finding_cwes from anon, authenticated;

alter table vulnassess.finding_assets enable row level security;
alter table vulnassess.finding_assets force row level security;
revoke all on vulnassess.finding_assets from anon, authenticated;

alter table vulnassess.vuln_intel enable row level security;
alter table vulnassess.vuln_intel force row level security;
revoke all on vulnassess.vuln_intel from anon, authenticated;

commit;
