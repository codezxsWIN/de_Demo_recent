-- 006 Context, scoring, and explainability: role predictions (with shadow
-- mode), contextual signals with evidence, preserved score history, and
-- advisory-only local-LLM analyst suggestions that must cite stored evidence.

begin;

create table if not exists vulnassess.role_predictions (
    id uuid primary key default gen_random_uuid(),
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    host_ip inet not null,
    predicted_role text not null,
    confidence real not null check (confidence between 0 and 1),
    features jsonb not null default '{}'::jsonb,
    evidence jsonb not null default '[]'::jsonb,
    model_version text not null,
    model_hash text not null,
    disposition text not null default 'shadow'
        check (disposition in ('accepted', 'rejected', 'shadow')),
    decided_by text,
    decided_at timestamptz,
    created_at timestamptz not null default now(),
    constraint role_predictions_unique unique (run_id, host_ip, model_hash)
);
comment on table vulnassess.role_predictions is
    'Host-role model output with the features and evidence used. Predictions '
    'are advisory until a disposition is recorded; shadow rows never feed the '
    'authoritative score.';

create index if not exists role_predictions_run_idx
    on vulnassess.role_predictions (run_id, host_ip);

create table if not exists vulnassess.context_signals (
    id uuid primary key default gen_random_uuid(),
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    host_ip inet not null,
    signal_kind text not null
        check (signal_kind in ('exposure', 'control', 'criticality',
                               'environment', 'override')),
    value jsonb not null,
    confidence real check (confidence between 0 and 1),
    source text not null check (source in ('model', 'config', 'manual', 'scanner')),
    evidence jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);
comment on table vulnassess.context_signals is
    'Every contextual input to scoring (exposure, controls, criticality, '
    'environment, manual overrides) with its source and the evidence behind it.';

create index if not exists context_signals_run_idx
    on vulnassess.context_signals (run_id, host_ip, signal_kind);

-- Append-only score history: `scores` holds the latest per (run, finding);
-- this table preserves every calculation, including re-scores, so the project
-- can answer why a finding moved between bands across runs.
create table if not exists vulnassess.score_history (
    id uuid primary key default gen_random_uuid(),
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    finding_id text not null references vulnassess.findings (id) on delete cascade,
    weights_hash text not null,
    formula_version text not null,
    cvss_inputs jsonb not null default '{}'::jsonb,
    epss_input jsonb not null default '{}'::jsonb,
    kev_input boolean not null default false,
    environmental jsonb not null default '{}'::jsonb,
    risk real not null check (risk between 0 and 100),
    band text not null,
    explanation text not null,
    recommendation text,
    calculated_at timestamptz not null default now()
);
comment on table vulnassess.score_history is
    'Every risk-score calculation with its formula/weights hash and full '
    'inputs, so any priority change between runs is fully explainable.';

create index if not exists score_history_finding_idx
    on vulnassess.score_history (finding_id, calculated_at desc);
create index if not exists score_history_run_idx
    on vulnassess.score_history (run_id, calculated_at desc);

-- Local-LLM analyst output is advisory only and must cite stored evidence.
create table if not exists vulnassess.analyst_suggestions (
    id uuid primary key default gen_random_uuid(),
    run_id text not null references vulnassess.runs (run_id) on delete cascade,
    finding_id text references vulnassess.findings (id) on delete cascade,
    host_ip inet,
    model text not null,
    suggestion text not null,
    cited_evidence jsonb not null default '[]'::jsonb,
    is_advisory boolean not null default true,
    created_at timestamptz not null default now(),
    constraint analyst_suggestions_advisory check (is_advisory)
);
comment on table vulnassess.analyst_suggestions is
    'Local-LLM analyst suggestions, permanently marked advisory; the check '
    'constraint refuses to store them as authoritative output.';

create index if not exists analyst_suggestions_run_idx
    on vulnassess.analyst_suggestions (run_id, created_at desc);

alter table vulnassess.role_predictions enable row level security;
alter table vulnassess.role_predictions force row level security;
revoke all on vulnassess.role_predictions from anon, authenticated;

alter table vulnassess.context_signals enable row level security;
alter table vulnassess.context_signals force row level security;
revoke all on vulnassess.context_signals from anon, authenticated;

alter table vulnassess.score_history enable row level security;
alter table vulnassess.score_history force row level security;
revoke all on vulnassess.score_history from anon, authenticated;

alter table vulnassess.analyst_suggestions enable row level security;
alter table vulnassess.analyst_suggestions force row level security;
revoke all on vulnassess.analyst_suggestions from anon, authenticated;

commit;
