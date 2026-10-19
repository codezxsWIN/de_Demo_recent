-- 003 Governance: engagements, authorisation, scope entries, frozen scope
-- snapshots, canary/exclusion enforcement, and audit trail links.
-- Every table lives in the private vulnassess schema with RLS enabled and no
-- grants for anon/authenticated, so the browser can never reach it directly.

begin;

create table if not exists vulnassess.engagements (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    owner_name text not null,
    department text,
    authorisation_ref text not null unique,
    authorised_from date not null,
    authorised_until date not null,
    permitted_tools text[] not null default '{}'::text[],
    scan_restrictions jsonb not null default '{}'::jsonb,
    status text not null default 'active'
        check (status in ('draft', 'active', 'expired', 'revoked')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint engagements_window_check check (authorised_until >= authorised_from)
);
comment on table vulnassess.engagements is
    'Approved assessment engagements: who owns the target set, under which '
    'authorisation reference, for how long, with which tools and restrictions.';

alter table vulnassess.assessment_targets
    add column if not exists engagement_id uuid
        references vulnassess.engagements (id) on delete cascade;
alter table vulnassess.assessment_targets
    add column if not exists entry_kind text not null default 'target'
        check (entry_kind in ('target', 'canary', 'exclusion'));
alter table vulnassess.assessment_targets
    add column if not exists owner_note text;
alter table vulnassess.assessment_targets
    add column if not exists expires_at date;

-- A canary or exclusion entry must never be usable as an ordinary scan target:
-- block any scan job that points at one.
create or replace function vulnassess.block_non_target_scan_jobs() returns trigger as $$
begin
    if new.target_id is null then
        return new;
    end if;
    if exists (
        select 1 from vulnassess.assessment_targets t
        where t.id = new.target_id and t.entry_kind <> 'target'
    ) then
        raise exception 'scan target % is a canary or exclusion entry and must not be scanned'
            using errcode = 'check_violation';
    end if;
    return new;
end;
$$ language plpgsql;

drop trigger if exists scan_jobs_target_kind_trigger on vulnassess.scan_jobs;
create trigger scan_jobs_target_kind_trigger
    before insert or update on vulnassess.scan_jobs
    for each row execute function vulnassess.block_non_target_scan_jobs();

create table if not exists vulnassess.scope_snapshots (
    id uuid primary key default gen_random_uuid(),
    engagement_id uuid not null
        references vulnassess.engagements (id) on delete cascade,
    run_id text references vulnassess.runs (run_id) on delete set null,
    snapshot jsonb not null,
    sha256 text not null,
    created_at timestamptz not null default now(),
    constraint scope_snapshots_run_unique unique (engagement_id, run_id)
);
comment on table vulnassess.scope_snapshots is
    'Frozen copy of the approved scope at the moment an assessment run or scan '
    'was requested, so later scope edits never rewrite history.';

alter table vulnassess.scan_jobs
    add column if not exists scope_snapshot_id uuid
        references vulnassess.scope_snapshots (id) on delete set null;
alter table vulnassess.scan_jobs
    add column if not exists operator text;
alter table vulnassess.scan_jobs
    add column if not exists tool_version text;
alter table vulnassess.scan_jobs
    add column if not exists error_summary text;
alter table vulnassess.scan_jobs
    add column if not exists result_counts jsonb not null default '{}'::jsonb;
alter table vulnassess.scan_jobs
    add column if not exists content_sha256 text;

alter table vulnassess.audit_events
    add column if not exists engagement_id uuid
        references vulnassess.engagements (id) on delete set null;
alter table vulnassess.audit_events
    add column if not exists scan_job_id uuid
        references vulnassess.scan_jobs (id) on delete set null;
create index if not exists audit_events_engagement_idx
    on vulnassess.audit_events (engagement_id, occurred_at desc);

create index if not exists assessment_targets_engagement_idx
    on vulnassess.assessment_targets (engagement_id, entry_kind);
create index if not exists scope_snapshots_engagement_idx
    on vulnassess.scope_snapshots (engagement_id, created_at desc);

alter table vulnassess.engagements enable row level security;
alter table vulnassess.engagements force row level security;
revoke all on vulnassess.engagements from anon, authenticated;

alter table vulnassess.scope_snapshots enable row level security;
alter table vulnassess.scope_snapshots force row level security;
revoke all on vulnassess.scope_snapshots from anon, authenticated;

commit;
