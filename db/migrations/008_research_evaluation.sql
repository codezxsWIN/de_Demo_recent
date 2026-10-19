-- 008 Model training and research evaluation: immutable datasets with
-- content hashes, labelled ground truth, role-model training runs with full
-- metrics, and reproducible scoring ablations.

begin;

create table if not exists vulnassess.datasets (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    version text not null,
    source text not null,
    data_kind text not null check (data_kind in ('synthetic', 'real_authorised')),
    reviewer text,
    quality text not null default 'draft'
        check (quality in ('draft', 'reviewed', 'approved')),
    config_hash text not null,
    content_sha256 text not null,
    row_count integer not null check (row_count >= 0),
    created_at timestamptz not null default now(),
    constraint datasets_unique unique (name, version, content_sha256)
);
comment on table vulnassess.datasets is
    'Registered datasets for training/evaluation. The content hash makes every '
    'experiment reproducible: the same hash always means the same rows.';

create table if not exists vulnassess.ground_truth_labels (
    id uuid primary key default gen_random_uuid(),
    dataset_id uuid not null references vulnassess.datasets (id) on delete cascade,
    subject_kind text not null
        check (subject_kind in ('host_role', 'exposure', 'control', 'priority')),
    subject_key text not null,
    label text not null,
    annotated_by text not null,
    created_at timestamptz not null default now(),
    constraint ground_truth_unique unique (dataset_id, subject_kind, subject_key)
);

create index if not exists ground_truth_dataset_idx
    on vulnassess.ground_truth_labels (dataset_id, subject_kind);

create table if not exists vulnassess.role_model_runs (
    id uuid primary key default gen_random_uuid(),
    dataset_id uuid not null references vulnassess.datasets (id) on delete restrict,
    model_name text not null,
    model_hash text not null,
    label_set text[] not null,
    split jsonb not null,
    accuracy real check (accuracy between 0 and 1),
    macro_f1 real check (macro_f1 between 0 and 1),
    per_class jsonb not null default '{}'::jsonb,
    coverage real check (coverage between 0 and 1),
    abstention_rate real check (abstention_rate between 0 and 1),
    confusion jsonb not null default '{}'::jsonb,
    evaluated_at timestamptz not null default now(),
    notes text
);
comment on table vulnassess.role_model_runs is
    'Role-model training/evaluation runs, pinned to an immutable dataset '
    'version and model hash, with full metrics including confusion matrix.';

create index if not exists role_model_runs_dataset_idx
    on vulnassess.role_model_runs (dataset_id, evaluated_at desc);

create table if not exists vulnassess.ablation_experiments (
    id uuid primary key default gen_random_uuid(),
    dataset_id uuid not null references vulnassess.datasets (id) on delete restrict,
    variant text not null
        check (variant in ('cvss_only', 'cvss_epss', 'full_context')),
    config_hash text not null,
    metrics jsonb not null default '{}'::jsonb,
    ranking jsonb not null default '[]'::jsonb,
    ranking_changes jsonb not null default '[]'::jsonb,
    created_at timestamptz not null default now(),
    constraint ablation_unique unique (dataset_id, variant, config_hash)
);
comment on table vulnassess.ablation_experiments is
    'Scoring ablations (CVSS-only vs CVSS+EPSS vs full context) with preserved '
    'rankings and the changes between variants, ready for the report.';

create index if not exists ablation_dataset_idx
    on vulnassess.ablation_experiments (dataset_id, variant);

alter table vulnassess.datasets enable row level security;
alter table vulnassess.datasets force row level security;
revoke all on vulnassess.datasets from anon, authenticated;

alter table vulnassess.ground_truth_labels enable row level security;
alter table vulnassess.ground_truth_labels force row level security;
revoke all on vulnassess.ground_truth_labels from anon, authenticated;

alter table vulnassess.role_model_runs enable row level security;
alter table vulnassess.role_model_runs force row level security;
revoke all on vulnassess.role_model_runs from anon, authenticated;

alter table vulnassess.ablation_experiments enable row level security;
alter table vulnassess.ablation_experiments force row level security;
revoke all on vulnassess.ablation_experiments from anon, authenticated;

commit;
