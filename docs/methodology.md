# Methodology

The canonical [project brief](PROJECT.md) now supplies the deck-derived pipeline
names, replacing the provisional day-zero sequence. This is a summary of that
supplied brief, not a verbatim transcription of an independently inspected slide deck.

1. **Target input.** Resolve requested targets and enforce the explicit lab scope
   before scanner execution.
2. **Scan orchestrator.** Discover with Nmap first, derive observed web endpoints,
   select tools, and record the run plan and outcomes.
3. **Safe scanning.** Use scoped, non-destructive scanner settings and preserve
   execution metadata, raw observations, coverage, and safety evidence.
4. **Unified result engine.** Normalize observations, justify duplicate merges,
   preserve every source, and expose evidence-based confidence.
5. **AI security analyst.** Infer context with rules; optionally ask a local Ollama
   model to correlate the selected target's complete stored evidence and propose an
   advisory remediation sequence. Validate every cited finding/evidence ID and never
   let model output overwrite canonical context, scores or records.
6. **CVE intelligence.** Match against dated, human-provided NVD, EPSS, and KEV
   snapshots offline, retaining uncertainty and match provenance.
7. **Report.** Present ranks, reasons, evidence, methodology, provenance,
   low-confidence findings, and later re-scan trends.
8. **Re-scan validation.** Distinguish justified fixes, still-open findings,
   regressions, and not-observable cases using comparable runs.

Risk ranking, expert evaluation, and the lab/demo are cross-cutting components.
Pipeline stage numbers are not the four implementation phases or a strict
execution schedule: intelligence matching precedes final unification, context,
ranking, and reporting. Formula and band definitions remain in [scoring.md](scoring.md).
Only the evaluation phase may tune the hypothesis, with recorded decisions and
held-out judgments.
