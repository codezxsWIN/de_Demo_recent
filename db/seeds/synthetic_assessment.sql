-- Authorised synthetic demonstration records for VulnAssess.
-- Every host, CVE label and finding below is invented for teaching demos;
-- CVE identifiers reference the synthetic feed snapshots shipped with the
-- project, not real vulnerable systems. Safe to load into any environment.
-- Idempotent: safe to re-run (all inserts use on conflict do nothing).
-- Apply to Supabase/PostgreSQL after db/migrations/*.sql.

begin;

-- Legacy core tables: the read-only dashboard renders from these. ----------
insert into vulnassess.runs (run_id, started_at, config_hash, summary_json) values
  ('synthetic-run-1', '2026-09-20T09:00:00+00:00', 'synthcfg00000001',
   '{"hosts": 3, "findings": 3, "label": "synthetic demonstration"}'),
  ('synthetic-run-2', '2026-09-21T09:00:00+00:00', 'synthcfg00000001',
   '{"hosts": 3, "findings": 3, "label": "synthetic demonstration rescan"}')
on conflict (run_id) do nothing;

insert into vulnassess.hosts (run_id, ip, json) values
  ('synthetic-run-1', '172.28.0.10',
   '{"ip":"172.28.0.10","hostname":"web.lab.invalid","os_guess":"linux","services":[{"port":443,"protocol":"tcp"}]}'),
  ('synthetic-run-1', '172.28.0.12',
   '{"ip":"172.28.0.12","hostname":"db.lab.invalid","os_guess":"linux","services":[{"port":5432,"protocol":"tcp"}]}'),
  ('synthetic-run-2', '172.28.0.10',
   '{"ip":"172.28.0.10","hostname":"web.lab.invalid","os_guess":"linux","services":[{"port":443,"protocol":"tcp"}]}'),
  ('synthetic-run-2', '172.28.0.12',
   '{"ip":"172.28.0.12","hostname":"db.lab.invalid","os_guess":"linux","services":[{"port":5432,"protocol":"tcp"}]}')
on conflict (run_id, ip) do nothing;

insert into vulnassess.cve (id, json, cvss31_base, cvss40_base) values
  ('CVE-1999-9001', '{"id":"CVE-1999-9001","summary":"Synthetic demo RCE placeholder"}', 9.8, 9.3),
  ('CVE-1999-9002', '{"id":"CVE-1999-9002","summary":"Synthetic demo info leak placeholder"}', 5.3, 5.1)
on conflict (id) do nothing;

insert into vulnassess.findings (id, run_id, host_ip, tool, json, first_seen, last_seen) values
  ('syn-finding-1', 'synthetic-run-1', '172.28.0.10', 'nmap',
   '{"id":"syn-finding-1","host_ip":"172.28.0.10","port":443,"protocol":"tcp","tool":"nmap","title":"Demo TLS service exposes synthetic RCE","description":"Synthetic demonstration finding (labelled).","evidence":"443/tcp open, synthetic banner","cve_ids":["CVE-1999-9001"],"cwe_ids":["CWE-78"],"native_severity":"high","native_confidence":0.9,"provenance":{"source":"synthetic"}}',
   '2026-09-20T09:05:00+00:00', '2026-09-21T09:05:00+00:00'),
  ('syn-finding-2', 'synthetic-run-1', '172.28.0.12', 'nikto',
   '{"id":"syn-finding-2","host_ip":"172.28.0.12","port":5432,"protocol":"tcp","tool":"nikto","title":"Demo database banner leaks version","description":"Synthetic demonstration finding (labelled).","evidence":"banner discloses synthetic version","cve_ids":["CVE-1999-9002"],"cwe_ids":["CWE-200"],"native_severity":"medium","native_confidence":0.7,"provenance":{"source":"synthetic"}}',
   '2026-09-20T09:06:00+00:00', '2026-09-21T09:06:00+00:00')
on conflict (id) do nothing;

insert into vulnassess.finding_runs (run_id, finding_id, seen_at) values
  ('synthetic-run-1', 'syn-finding-1', '2026-09-20T09:05:00+00:00'),
  ('synthetic-run-2', 'syn-finding-1', '2026-09-21T09:05:00+00:00'),
  ('synthetic-run-1', 'syn-finding-2', '2026-09-20T09:06:00+00:00'),
  ('synthetic-run-2', 'syn-finding-2', '2026-09-21T09:06:00+00:00')
on conflict (run_id, finding_id) do nothing;

insert into vulnassess.enrichments (finding_id, cve_id, json) values
  ('syn-finding-1', 'CVE-1999-9001', '{"cvss31_base":9.8,"epss":0.91,"kev":true,"label":"synthetic"}'),
  ('syn-finding-2', 'CVE-1999-9002', '{"cvss31_base":5.3,"epss":0.12,"kev":false,"label":"synthetic"}')
on conflict (finding_id, cve_id) do nothing;

insert into vulnassess.epss (cve, epss, percentile, score_date) values
  ('CVE-1999-9001', 0.91, 99.2, '2026-09-01'),
  ('CVE-1999-9002', 0.12, 61.0, '2026-09-01')
on conflict (cve) do nothing;

insert into vulnassess.kev (cve, json) values
  ('CVE-1999-9001', '{"cveID":"CVE-1999-9001","label":"synthetic demo entry"}')
on conflict (cve) do nothing;

-- Governance ----------------------------------------------------------------
insert into vulnassess.engagements (id, name, owner_name, department, authorisation_ref,
    authorised_from, authorised_until, permitted_tools, scan_restrictions, status) values
  ('11111111-1111-4111-8111-111111111111', 'College lab assessment (synthetic)',
   'Lab supervisor', 'Computing department', 'AUTH-SYNTH-2026-001',
   '2026-09-01', '2026-09-30', '{"nmap","zap","nikto"}',
   '{"no_dos": true, "business_hours_only": true}', 'active')
on conflict (authorisation_ref) do nothing;

insert into vulnassess.assessment_targets (id, label, scope_ref, target_kind, target_value,
    authorization_ref, engagement_id, entry_kind, owner_note, expires_at) values
  ('22222222-2222-4222-8222-000000000001', 'Lab web frontend', 'AUTH-SYNTH-2026-001', 'ip',
   '172.28.0.10', 'AUTH-SYNTH-2026-001', '11111111-1111-4111-8111-111111111111', 'target',
   'Teaching lab web host', '2026-09-30'),
  ('22222222-2222-4222-8222-000000000002', 'Lab database', 'AUTH-SYNTH-2026-001', 'ip',
   '172.28.0.12', 'AUTH-SYNTH-2026-001', '11111111-1111-4111-8111-111111111111', 'target',
   'Teaching lab database host', '2026-09-30'),
  ('22222222-2222-4222-8222-000000000003', 'Out-of-scope canary', 'AUTH-SYNTH-2026-001', 'ip',
   '10.255.255.9', 'AUTH-SYNTH-2026-001', '11111111-1111-4111-8111-111111111111', 'canary',
   'Probe outside the fence; must never be scanned', null)
on conflict (scope_ref, target_kind, target_value) do nothing;

insert into vulnassess.scope_snapshots (id, engagement_id, run_id, snapshot, sha256) values
  ('33333333-3333-4333-8333-000000000001', '11111111-1111-4111-8111-111111111111',
   'synthetic-run-1',
   '{"targets":["172.28.0.10","172.28.0.12"],"canary":"10.255.255.9","permitted_tools":["nmap","zap","nikto"]}',
   'synthscopehash0000000000000000000000000000000000000000000000000001'),
  ('33333333-3333-4333-8333-000000000002', '11111111-1111-4111-8111-111111111111',
   'synthetic-run-2',
   '{"targets":["172.28.0.10","172.28.0.12"],"canary":"10.255.255.9","permitted_tools":["nmap","zap","nikto"]}',
   'synthscopehash0000000000000000000000000000000000000000000000000002')
on conflict (engagement_id, run_id) do nothing;

insert into vulnassess.scan_jobs (id, target_id, run_id, tool, status, requested_at, started_at,
    completed_at, scope_snapshot_id, scope_snapshot, command_summary, operator, tool_version,
    result_counts, content_sha256) values
  ('44444444-4444-4444-8444-000000000001', '22222222-2222-4222-8222-000000000001',
   'synthetic-run-1', 'nmap', 'completed', '2026-09-20T09:00:00+00:00',
   '2026-09-20T09:01:00+00:00', '2026-09-20T09:10:00+00:00',
   '33333333-3333-4333-8333-000000000001',
   '{"targets":["172.28.0.10"],"canary":"10.255.255.9"}', 'nmap -sV -p 1-1000 172.28.0.10',
   'student-analyst', '7.94', '{"hosts":1,"services":2}', 'synthnmaphash0001'),
  ('44444444-4444-4444-8444-000000000002', '22222222-2222-4222-8222-000000000002',
   'synthetic-run-2', 'nikto', 'completed', '2026-09-21T09:00:00+00:00',
   '2026-09-21T09:01:00+00:00', '2026-09-21T09:12:00+00:00',
   '33333333-3333-4333-8333-000000000002',
   '{"targets":["172.28.0.12"],"canary":"10.255.255.9"}', 'nikto -h 172.28.0.12',
   'student-analyst', '2.5.0', '{"findings":1}', 'synthniktohash002')
on conflict (id) do nothing;

-- Assets and service history -------------------------------------------------
insert into vulnassess.assets (id, target_id, run_id, address, hostname, asset_role,
    criticality, environment, os_guess, mac, source_scan_id, tags, observed_at) values
  ('55555555-5555-4555-8555-000000000001', '22222222-2222-4222-8222-000000000001',
   'synthetic-run-1', '172.28.0.10', 'web.lab.invalid', 'web_frontend', 'high', 'prod',
   'linux 5.x', '02:42:ac:1c:00:0a', '44444444-4444-4444-8444-000000000001',
   '["internet_facing","synthetic"]', '2026-09-20T09:10:00+00:00'),
  ('55555555-5555-4555-8555-000000000002', '22222222-2222-4222-8222-000000000002',
   'synthetic-run-1', '172.28.0.12', 'db.lab.invalid', 'database', 'critical', 'prod',
   'linux 5.x', '02:42:ac:1c:00:0c', '44444444-4444-4444-8444-000000000002',
   '["internal","synthetic"]', '2026-09-20T09:10:00+00:00')
on conflict (target_id, run_id, address, hostname) do nothing;

insert into vulnassess.services (id, asset_id, port, transport, name, product, version, cpe, tls,
    observed_at) values
  ('66666666-6666-4666-8666-000000000001', '55555555-5555-4555-8555-000000000001', 443, 'tcp',
   'https', 'synthetic-web', '2.4', 'cpe:/a:synthetic:web:2.4', true,
   '2026-09-20T09:10:00+00:00'),
  ('66666666-6666-4666-8666-000000000002', '55555555-5555-4555-8555-000000000002', 5432, 'tcp',
   'postgres', 'synthetic-db', '15', 'cpe:/a:synthetic:db:15', false,
   '2026-09-20T09:10:00+00:00')
on conflict (asset_id, port, transport) do nothing;

insert into vulnassess.service_observations (id, asset_id, scan_job_id, port, transport, name,
    product, version, cpe, tls, banner, state, evidence_source, observed_at) values
  ('77777777-7777-4777-8777-000000000001', '55555555-5555-4555-8555-000000000001',
   '44444444-4444-4444-8444-000000000001', 443, 'tcp', 'https', 'synthetic-web', '2.4',
   'cpe:/a:synthetic:web:2.4', true, 'synthetic banner (labelled)', 'open', 'nmap',
   '2026-09-20T09:10:00+00:00'),
  ('77777777-7777-4777-8777-000000000002', '55555555-5555-4555-8555-000000000002',
   '44444444-4444-4444-8444-000000000002', 5432, 'tcp', 'postgres', 'synthetic-db', '15',
   'cpe:/a:synthetic:db:15', false, 'synthetic db banner (labelled)', 'open', 'nikto',
   '2026-09-21T09:12:00+00:00')
on conflict (asset_id, port, transport, observed_at) do nothing;

insert into vulnassess.asset_relationships (id, from_asset, to_asset, relation, evidence,
    scan_job_id) values
  ('88888888-8888-4888-8888-000000000001', '55555555-5555-4555-8555-000000000001',
   '55555555-5555-4555-8555-000000000002', 'depends_on',
   '{"reason":"web config references db host (synthetic evidence)","label":"synthetic"}',
   '44444444-4444-4444-8444-000000000001')
on conflict (from_asset, to_asset, relation) do nothing;

-- Findings lifecycle, mappings, intel ----------------------------------------
update vulnassess.findings set
    title = 'Demo TLS service exposes synthetic RCE',
    severity = 'high', confidence = 0.9, port = 443, lifecycle_status = 'open',
    recurrence_count = 1,
    asset_id = '55555555-5555-4555-8555-000000000001',
    scan_job_id = '44444444-4444-4444-8444-000000000001'
  where id = 'syn-finding-1';
update vulnassess.findings set
    title = 'Demo database banner leaks version',
    severity = 'medium', confidence = 0.7, port = 5432, lifecycle_status = 'open',
    asset_id = '55555555-5555-4555-8555-000000000002',
    scan_job_id = '44444444-4444-4444-8444-000000000002'
  where id = 'syn-finding-2';

insert into vulnassess.finding_cves (finding_id, cve_id, source_tool, confidence) values
  ('syn-finding-1', 'CVE-1999-9001', 'nmap', 0.85),
  ('syn-finding-2', 'CVE-1999-9002', 'nikto', 0.6)
on conflict (finding_id, cve_id) do nothing;

insert into vulnassess.finding_cwes (finding_id, cwe_id, source) values
  ('syn-finding-1', 'CWE-78', 'scanner'),
  ('syn-finding-2', 'CWE-200', 'scanner')
on conflict (finding_id, cwe_id) do nothing;

insert into vulnassess.finding_assets (finding_id, asset_id) values
  ('syn-finding-1', '55555555-5555-4555-8555-000000000001'),
  ('syn-finding-2', '55555555-5555-4555-8555-000000000002')
on conflict (finding_id, asset_id) do nothing;

insert into vulnassess.vuln_intel (cve_id, cvss31_vector, cvss31_base, epss_score,
    epss_percentile, epss_date, in_kev, exploit_maturity, patch_references,
    remediation_guidance, feed_source, feed_date) values
  ('CVE-1999-9001', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 0.91, 99.2,
   '2026-09-01', true, 'weaponized', '["https://example.invalid/patch/synthetic-9001"]',
   'Apply the synthetic vendor patch (demo).', 'synthetic-feed', '2026-09-01'),
  ('CVE-1999-9002', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3, 0.12, 61.0,
   '2026-09-01', false, 'poc', '[]', 'Suppress the version banner (demo).',
   'synthetic-feed', '2026-09-01')
on conflict (cve_id) do nothing;

insert into vulnassess.scan_evidence (id, scan_job_id, finding_id, evidence_type, excerpt,
    source_sha256, provenance) values
  ('99999999-9999-4999-8999-000000000001', '44444444-4444-4444-8444-000000000001',
   'syn-finding-1', 'nmap-excerpt',
   '443/tcp open https synthetic-web 2.4 (synthetic banner; no raw export stored)',
   'synthevidencehash001', '{"parser":"nmap","raw_file":"not retained by policy"}'),
  ('99999999-9999-4999-8999-000000000002', '44444444-4444-4444-8444-000000000002',
   'syn-finding-2', 'nikto-excerpt',
   'banner discloses synthetic-db 15 (synthetic excerpt)',
   'synthevidencehash002', '{"parser":"nikto","raw_file":"not retained by policy"}')
on conflict (id) do nothing;

-- Scoring, explainability ----------------------------------------------------
insert into vulnassess.role_predictions (id, run_id, host_ip, predicted_role, confidence,
    features, evidence, model_version, model_hash, disposition) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-000000000001', 'synthetic-run-1', '172.28.0.10', 'web_frontend',
   0.93, '{"open_ports":[443],"tls":true}', '["https on 443 (synthetic evidence)"]',
   'role-clf-demo', 'synthmodelhash0001', 'accepted')
on conflict (run_id, host_ip, model_hash) do nothing;

insert into vulnassess.context_signals (id, run_id, host_ip, signal_kind, value, confidence,
    source, evidence) values
  ('bbbbbbbb-bbbb-4bbb-8bbb-000000000001', 'synthetic-run-1', '172.28.0.10', 'exposure',
   '"internet_facing"', 0.9, 'scanner', '{"reason":"reachable from lab gateway","label":"synthetic"}'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-000000000002', 'synthetic-run-1', '172.28.0.12', 'control',
   '{"waf": false, "auth_required": true}', 0.8, 'scanner', '{"banner":"synthetic auth prompt"}')
on conflict (id) do nothing;

insert into vulnassess.score_history (id, run_id, finding_id, weights_hash, formula_version,
    cvss_inputs, epss_input, kev_input, environmental, risk, band, explanation,
    recommendation, calculated_at) values
  ('cccccccc-cccc-4ccc-8ccc-000000000001', 'synthetic-run-1', 'syn-finding-1', 'synthw1', '1',
   '{"cvss31_base":9.8}', '{"epss":0.91,"percentile":99.2}', false,
   '{"exposure":"internal","waf":false}', 55.0, 'Medium',
   'Internal-only exposure keeps this below High despite CVSS 9.8 (synthetic).',
   'Confirm exposure before escalating.', '2026-09-20T10:00:00+00:00'),
  ('cccccccc-cccc-4ccc-8ccc-000000000002', 'synthetic-run-2', 'syn-finding-1', 'synthw2', '1',
   '{"cvss31_base":9.8}', '{"epss":0.91,"percentile":99.2}', true,
   '{"exposure":"internet_facing","waf":false}', 84.0, 'High',
   'Rescan found the host reachable from the gateway and the CVE is KEV-listed: risk rises to High (synthetic).',
   'Patch within 7 days.', '2026-09-21T10:00:00+00:00')
on conflict (id) do nothing;

insert into vulnassess.analyst_suggestions (id, run_id, finding_id, host_ip, model, suggestion,
    cited_evidence) values
  ('dddddddd-dddd-4ddd-8ddd-000000000001', 'synthetic-run-2', 'syn-finding-1', '172.28.0.10',
   'local-llm-demo',
   'Advisory: the KEV listing plus gateway reachability justify High priority.',
   '["99999999-9999-4999-8999-000000000001"]')
on conflict (id) do nothing;

-- Review workflow ------------------------------------------------------------
insert into vulnassess.review_decisions (id, finding_id, run_id, reviewer, decision,
    justification, supporting_evidence) values
  ('eeeeeeee-eeee-4eee-8eee-000000000001', 'syn-finding-1', 'synthetic-run-2', 'lab supervisor',
   'accepted', 'Evidence confirms the synthetic RCE exposure on the demo web host.',
   '["99999999-9999-4999-8999-000000000001"]')
on conflict (id) do nothing;

insert into vulnassess.remediation_tracking (id, finding_id, status, owner, verification_run_id,
    evidence) values
  ('eeeeeeee-eeee-4eee-8eee-000000000002', 'syn-finding-1', 'in_progress', 'lab ops', null,
   '{"note":"patch scheduled; not verified yet"}')
on conflict (finding_id) do nothing;

insert into vulnassess.comments (id, finding_id, run_id, author, body) values
  ('eeeeeeee-eeee-4eee-8eee-000000000003', 'syn-finding-1', null, 'student-analyst',
   'Plain-text note: recheck after the next lab window.')
on conflict (id) do nothing;

-- Research evaluation ---------------------------------------------------------
insert into vulnassess.datasets (id, name, version, source, data_kind, reviewer, quality,
    config_hash, content_sha256, row_count) values
  ('ffffffff-ffff-4fff-8fff-000000000001', 'synthetic-role-lab', '1.0.0',
   'project synthetic generator', 'synthetic', 'lab supervisor', 'approved', 'synthcfg00000001',
   'synthdatasethash001', 60)
on conflict (name, version, content_sha256) do nothing;

insert into vulnassess.ground_truth_labels (id, dataset_id, subject_kind, subject_key, label,
    annotated_by) values
  ('ffffffff-ffff-4fff-8fff-000000000002', 'ffffffff-ffff-4fff-8fff-000000000001',
   'host_role', '172.28.0.10', 'web_frontend', 'lab supervisor'),
  ('ffffffff-ffff-4fff-8fff-000000000003', 'ffffffff-ffff-4fff-8fff-000000000001',
   'host_role', '172.28.0.12', 'database', 'lab supervisor'),
  ('ffffffff-ffff-4fff-8fff-000000000004', 'ffffffff-ffff-4fff-8fff-000000000001',
   'priority', 'syn-finding-1', 'High', 'lab supervisor')
on conflict (dataset_id, subject_kind, subject_key) do nothing;

insert into vulnassess.role_model_runs (id, dataset_id, model_name, model_hash, label_set, split,
    accuracy, macro_f1, per_class, coverage, abstention_rate, confusion, notes) values
  ('ffffffff-ffff-4fff-8fff-000000000005', 'ffffffff-ffff-4fff-8fff-000000000001',
   'role-clf-demo', 'synthmodelhash0001', '{"web_frontend","database","unknown"}',
   '{"train":0.8,"validation":0.2,"seed":42}', 0.92, 0.89,
   '{"web_frontend":{"precision":0.95,"recall":0.9,"f1":0.92},"database":{"precision":0.9,"recall":0.9,"f1":0.9}}',
   0.97, 0.03, '{"web_frontend":{"web_frontend":27,"database":1},"database":{"web_frontend":2,"database":30}}',
   'Synthetic demonstration evaluation (labelled).')
on conflict (id) do nothing;

insert into vulnassess.ablation_experiments (id, dataset_id, variant, config_hash, metrics,
    ranking, ranking_changes) values
  ('ffffffff-ffff-4fff-8fff-000000000006', 'ffffffff-ffff-4fff-8fff-000000000001', 'cvss_only',
   'synthablationcfg1', '{"ndcg":0.71,"top1_accuracy":0.6}', '["syn-finding-1","syn-finding-2"]',
   '[]'),
  ('ffffffff-ffff-4fff-8fff-000000000007', 'ffffffff-ffff-4fff-8fff-000000000001', 'cvss_epss',
   'synthablationcfg1', '{"ndcg":0.78,"top1_accuracy":0.7}', '["syn-finding-1","syn-finding-2"]',
   '[{"position":0,"note":"EPSS lifts the KEV finding further from the rest"}]'),
  ('ffffffff-ffff-4fff-8fff-000000000008', 'ffffffff-ffff-4fff-8fff-000000000001',
   'full_context', 'synthablationcfg1', '{"ndcg":0.88,"top1_accuracy":0.85}',
   '["syn-finding-1","syn-finding-2"]',
   '[{"position":0,"note":"context separates the internet-facing host from the isolated one"}]')
on conflict (dataset_id, variant, config_hash) do nothing;

-- Retention policy defaults ----------------------------------------------------
insert into vulnassess.retention_policies (table_name, retention_days, basis) values
  ('scan_evidence', 365, 'authorised assessment window plus review year'),
  ('service_observations', 730, 'asset history for trend analysis'),
  ('score_history', 1095, 'explainability archive for assessment reports')
on conflict (table_name) do nothing;

-- Audit trail -------------------------------------------------------------------
insert into vulnassess.audit_events (run_id, engagement_id, scan_job_id, event_type, actor,
    detail, occurred_at) values
  (null, '11111111-1111-4111-8111-111111111111', null, 'engagement.created', 'lab supervisor',
   '{"label":"synthetic"}', '2026-09-01T08:00:00+00:00'),
  ('synthetic-run-1', '11111111-1111-4111-8111-111111111111',
   '44444444-4444-4444-8444-000000000001', 'scan.requested', 'student-analyst',
   '{"tool":"nmap"}', '2026-09-20T09:00:00+00:00'),
  ('synthetic-run-1', '11111111-1111-4111-8111-111111111111',
   '44444444-4444-4444-8444-000000000001', 'scan.completed', 'backend',
   '{"status":"completed"}', '2026-09-20T09:10:00+00:00')
on conflict do nothing;

commit;
