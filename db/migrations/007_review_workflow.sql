-- 007 Human review and workflow: reviewer decisions, remediation tracking
-- with verification evidence, and free-text comments (stored as untrusted
-- plain text, never rendered as HTML by the UI).

begin;

create table if not exists vulnassess.review_decisions (
    id uuid primary key default gen_random_uuid(),
    finding_id text not null references vulnassess.findings (id) on delete cascade,
    run_id text references vulnassess.runs (run_id) on delete set null,
    reviewer text not null,
    decision text not null
        check (decision in ('accepted', 'false_positive', 'needs_investigation',
                            'remediated', 'risk_accepted', 'duplicate',
                            'out_of_scope')),
    justification text not null check (char_length(justification) <= 4000),
    supporting_evidence jsonb not null default '[]'::jsonb,
    remediation_owner text,
    remediation_due date,
    decided_at timestamptz not null default now()
);
comment on table vulnassess.review_decisions is
    'Append-only reviewer decisions. The newest decision per finding defines '
    'its review state; earlier decisions remain as history.';

create index if not exists review_decisions_finding_idx
    on vulnassess.review_decisions (finding_id, decided_at desc);

create table if not exists vulnassess.remediation_tracking (
    id uuid primary key default gen_random_uuid(),
    finding_id text not null
        constraint remediation_tracking_finding_unique unique
        references vulnassess.findings (id) on delete cascade,
    status text not null default 'planned'
        check (status in ('planned', 'in_progress', 'pending_verification',
                          'verified', 'rejected')),
    owner text,
    verification_run_id text references vulnassess.runs (run_id) on delete set null,
    evidence jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);
comment on table vulnassess.remediation_tracking is
    'Fix status per finding. "verified" requires a verification run that '
    'confirms the finding no longer appears; nothing is marked fixed on '
    'trust alone.';

create index if not exists remediation_tracking_finding_idx
    on vulnassess.remediation_tracking (finding_id, updated_at desc);

create table if not exists vulnassess.comments (
    id uuid primary key default gen_random_uuid(),
    finding_id text references vulnassess.findings (id) on delete cascade,
    run_id text references vulnassess.runs (run_id) on delete cascade,
    author text not null,
    body text not null check (char_length(body) between 1 and 4000),
    created_at timestamptz not null default now(),
    constraint comments_scope check (finding_id is not null or run_id is not null)
);
comment on table vulnassess.comments is
    'Analyst notes. Body text is untrusted content: the UI must insert it as '
    'text only, never as HTML.';

create index if not exists comments_finding_idx
    on vulnassess.comments (finding_id, created_at desc);

alter table vulnassess.review_decisions enable row level security;
alter table vulnassess.review_decisions force row level security;
revoke all on vulnassess.review_decisions from anon, authenticated;

alter table vulnassess.remediation_tracking enable row level security;
alter table vulnassess.remediation_tracking force row level security;
revoke all on vulnassess.remediation_tracking from anon, authenticated;

alter table vulnassess.comments enable row level security;
alter table vulnassess.comments force row level security;
revoke all on vulnassess.comments from anon, authenticated;

commit;
