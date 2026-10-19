# VulnAssess explained simply

**A guide for teammates, teachers, reviewers, and people seeing the project for the first time**

Updated: 17 October 2026. Committed baseline: `6f523f6`, with additional uncommitted work and known unfinished parts identified below. This is an explanation of the project, not a claim that the current development version is ready for release.

For code, formulas, contracts, and detailed limitations, read the [complete technical reference](TECHNICAL_PROJECT_REFERENCE.md).

## Start here: the 30-second version

VulnAssess brings scanner results, public vulnerability information, machine context, and AI explanations into one place. It helps someone decide what deserves attention first and inspect the evidence behind that decision.

The scanner observes. The intelligence sources add known vulnerability facts. Context explains where the weakness sits. Fixed rules calculate the priority. AI explains and suggests checks. Validation decides whether the AI answer is acceptable to display.

The tool does not promise to find everything, prove a computer is safe, or automatically fix it. Some advanced features are previews or unfinished. The audit has repaired specific completion/freshness defects, but that is not a guarantee that every defect has been found. Those limits are explained rather than hidden.

**Reading route:** sections 1-12 explain the main idea; sections 13-18 explain what users can do; sections 19-24 explain evidence, limits, and presentation; sections 25-27 help you read a result without technical knowledge. Sections 28-30 help you choose a mode, recognise a trustworthy assessment, and explain the project to someone else.

If you only have two minutes, read the 30-second version above, [what the AI does](#9-what-does-the-ai-actually-do), [how to read a result](#25-how-to-read-a-result-without-being-a-security-expert), and [the current limits](#21-what-is-included-now-and-what-remains).

### Who is this guide for?

- **A teammate joining the project:** understand the purpose, the parts, and what is unfinished without opening the code first.
- **A teacher or project reviewer:** see what the team built, what the AI contributes, and what still needs independent proof.
- **Someone using an assessment result:** learn which observations matter, what the priority means, and what to do next.
- **A developer who needs exact implementation details:** start here for the big picture, then use the [technical reference](TECHNICAL_PROJECT_REFERENCE.md) for files, formulas, limits, and checks.

### Keep these four things separate

**A service** is something reachable, such as a web server. **A finding** is a recorded potential weakness. **A priority** is the tool's calculated order of attention. **An AI explanation** is an interpretation of supplied evidence.

Finding a service does not automatically mean finding a vulnerability. A convincing explanation does not become a new observation. A high priority is not a prediction that an attack will definitely happen.

### Before someone uses it

Use only a computer or lab target that the person is authorised to assess and that the app permits. Choose whether to collect new evidence, import a report, review an old result, or check the local computer. Confirm which tools and evidence sources that mode actually uses. Decide whether any permitted cloud analysis may receive the selected evidence. This guide does not grant permission to scan someone else's system or share private data.

## 1. What is VulnAssess?

VulnAssess is an AI-assisted network vulnerability assessment tool that runs primarily on your own computer.

It collects security observations, organises them, adds public vulnerability information, considers the type of machine involved, and produces a list of what deserves attention first. AI helps explain that evidence and can propose certain follow-up checks.

The goal is to answer:

> What did we find, why does it matter here, what should we investigate or fix first, and how certain are we?

It is designed to make the reasoning visible. A user should be able to trace an important conclusion back to an observation and see what was not checked.

## 2. Why is another assessment tool useful?

A normal scanner can produce a long list of alerts. That list still leaves difficult questions:

- Are several tools describing the same issue?
- Is this serious on this particular machine?
- Is the vulnerability known to be exploited?
- Was a protective control actually seen?
- Is the AI explaining real evidence or making an assumption?
- Does a disappearing alert mean the issue was fixed, or was it simply not checked again?

VulnAssess brings these questions into one assessment workflow. The project combines scanner evidence, public intelligence, deployment context, deterministic priorities, and checked AI explanations.

## 3. A simple example

Imagine two machines with the same software vulnerability.

One supports a public service used by customers. The other is a test machine used inside a lab. The underlying vulnerability can have the same standard severity score, while the operational importance of the machines differs.

VulnAssess tries to capture that difference. It also considers public information about exploitation and records the reasons behind its priority.

This is an illustration of the project's idea, not a claim that every public service is more important than every internal machine. A sensitive internal database can also be extremely important, and the tool can only reason from the evidence and metadata it has.

## 4. What happens during an assessment?

The normal sequence is:

1. **Choose a target you are authorised to assess.** The app checks it against its configured scope.
2. **Collect or import evidence.** Nmap and eligible Nikto checks can collect observations; existing Nessus and other supported reports can be imported.
3. **Organise the results.** Different report formats become consistent host, service, and finding records.
4. **Add vulnerability intelligence.** Supported CVEs are connected to NVD, EPSS, and CISA KEV information.
5. **Infer context.** The app estimates the machine's role, exposure, and observed protections.
6. **Calculate priorities.** Published rules and arithmetic produce a score and an explanation.
7. **Ask AI to interpret the case.** The model works from the supplied evidence.
8. **Validate the answer.** Unsupported references, changed scores, and malformed output are rejected.
9. **Show the result.** The user sees priorities, evidence, uncertainties, coverage, and useful next steps.

There are also saved assessments, comparison tools, and a separate self-defence section.

## 5. The tools inside it

### Nmap: what services are visible?

Nmap identifies open ports and services, such as HTTP, SSH, or a database. Some scan profiles can provide vulnerability-script output as well.

The browser's usual scan is deliberately light: the common 100 TCP ports and light service detection. It may find several services and zero vulnerability findings. That is a valid inventory result, although it is limited vulnerability coverage.

### Nikto: what web-server problems are visible?

Nikto checks supported web endpoints for certain server issues. It only makes sense where a suitable web service is available and the selected path permits it. A Redis database is not an HTTP website, so Nikto would not apply there.

### Nessus: bring in an existing vulnerability report

The app can read a completed Nessus report in `.nessus` format. It verifies that the report belongs to the selected authorised target. It does not start Nessus itself.

### Other supported evidence

The project retains a ZAP report reader and a narrow Redis configuration check. These are specific capabilities, not proof that every possible scanner or vulnerability is covered.

## 6. What are NVD, EPSS, and CISA KEV?

These are information sources, not extra scanners.

- **NVD** provides published CVE descriptions, available severity information, affected-product details, and references.
- **EPSS** provides exploitation-likelihood information and a relative percentile.
- **CISA KEV** identifies vulnerabilities in its known-exploited catalogue.

The app can read supplied local snapshots or perform limited public lookups for identified CVEs. It records dates and distinguishes cached information from fresh collection.

An open port by itself does not tell these sources which vulnerability is present. The assessment needs a supported CVE association before the targeted intelligence path becomes useful.

## 7. What does “context” mean?

Context means the circumstances of the affected machine.

The current app considers:

- **Role:** does the evidence resemble a web server, database, workstation, mail server, or another supported type?
- **Exposure:** is the address public, or is there metadata indicating an external viewpoint?
- **Controls:** were signals of authentication, TLS, a WAF, or rate limiting observed?
- **Approved metadata:** is this a test environment, and has an owner supplied criticality information?

Each inferred feature includes supporting text, a source, and confidence. A missing observation remains unknown.

Owner-supplied external-vantage information is not something the scanner discovered. Newly calculated profiles now label that exposure as manual; older saved profiles keep their history and are checked by their supporting text as well. The exposure estimate and numerical priority are not changed merely to correct the source label.

Port numbers alone do not establish a service's protocol or encryption. In the latest repair, a service using port 443 is no longer automatically labelled as TLS-protected, and a non-web service on port 80 does not automatically trigger Nikto. The tool still relies on the scanner's classification; that is not an independent proof that a service is secure.

These are estimates from available evidence. The tool does not automatically understand every firewall rule, VPN, network route, or business dependency.

## 8. How does the priority score work?

The app uses deterministic rules to calculate the official project priority. The AI does not choose that number.

The calculation can combine:

- The vulnerability's available CVSS information.
- Context-based Environmental adjustments.
- EPSS percentile.
- Known exploitation from KEV.

If some information is missing, the result explains that. A configured scanner-native fallback can be used when a supported CVSS calculation is unavailable. It is labelled separately rather than presented as a CVSS calculation. Missing severity is not replaced with a reassuring number.

The project bands are Critical, High, Medium, and Low. A high number means a high priority according to the configured method. It is not a percentage chance that the machine will be hacked.

Not every number uses every source. When the tool falls back to a scanner's configured native priority, that calculation does not use the EPSS multiplier or the usual Environmental adjustments. Known-exploited status can still affect it. The score breakdown shows which route was used.

Previously, missing both usable vulnerability severity and a configured fallback could yield `0 / Low`. The repaired code instead keeps such a finding **unscored** and records why a number could not be justified. That is different from a genuine zero calculated from valid inputs. Unscored findings are shown explicitly, and recognised older unsupported priorities carry a warning without rewriting their stored values. The exact verification is recorded in technical-reference section 40.11. An unexplained zero must not be treated as reassurance.

The current Environmental calculation uses CVSS v3.1. The app can retain v4.0 information, but that is not a complete v4.0 calculation engine.

## 9. What does the AI actually do?

The AI can:

- Explain why the observed findings matter for this target.
- Describe how context affects the assessment.
- Suggest an order for investigation or remediation.
- Identify a supported relationship between observations.
- State a hypothesis, a way to verify it, and an alternative explanation.
- Propose a small supported scan plan for a human to approve.
- Request a limited follow-up observation for a human to approve.

It receives selected evidence and existing scores. It does not have unrestricted control over the computer or permission to authorise targets.

There is also a separate learned asset-role classifier. That model is currently used for shadow predictions and evaluation rather than controlling official scores.

## 10. What stops the AI from making things up?

The application requires a structured response with evidence references and claim metadata. It rejects unknown vulnerability IDs, unsupported host/port references, changed scores, and certain unsupported assertions.

It also treats scanned text as untrusted. A malicious banner that says “ignore your instructions” must be handled as data. An instruction-detection sentinel sends the AI result to review.

These checks reduce specific failures. They do not guarantee that every sentence is correct. A model can misunderstand evidence even when it cites a real record. Users should be able to open and inspect the supporting observation.

## 11. Why can the scan finish when AI fails?

Evidence collection and AI interpretation have separate outcomes.

If Nmap succeeds and a model times out, the app can still show the collected services, findings, calculated priorities, and coverage limits. It labels the AI as unavailable.

If a model returns unsupported content, the app labels it Needs review and withholds the rejected answer. The scanner evidence is still useful.

When explicitly enabled for an eligible cloud choice, the app can try another configured provider after an availability failure. It does not use fallback to bypass a rejected unsafe answer.

## 12. Why are some workflow nodes grey?

A grey stage does not always mean the application is broken.

- No CVE was identified: targeted CVE intelligence may not apply.
- No HTTP service was observed: Nikto may not apply.
- No Nessus report was imported: the Nessus source was not used.
- No findings exist: there is no vulnerability-priority queue to calculate.
- No expert judgments were supplied: expert evaluation cannot run meaningfully.
- No comparable later assessment exists: re-scan comparison has no second input.

The UI distinguishes executed, not applicable, outside this run mode, failed, waiting, and running. The useful question is whether the chosen assessment had appropriate coverage, rather than whether every possible node became green.

## 13. What can I see in the interface?

The recorded workbench has Evidence, Context, Risk, and Findings views.

The workflow workspace adds:

- An overview of the assessment outcome.
- A graph or stage list showing the evidence flow.
- Inspectors for data, context, and citations.
- AI interpretation and next steps.
- Self-defence.
- Saved assessments.

Nodes can be moved and the graph can be zoomed. Those actions organise the view; they do not change the permitted scan operations.

Preview animations are demonstrations. They do not scan a target or create assessment evidence.

## 14. What is Self-defence?

Self-defence checks the computer running VulnAssess. On the current Windows implementation, it can inspect:

- Firewall profiles and active network profiles.
- Defender real-time protection.
- Registered antivirus names.
- Remote Desktop and SMB1 settings.
- Secure Boot and system-drive encryption status.
- Pending update restart and latest recorded hotfix date.
- Listening TCP ports and application names.

The result gives plain-language precautions, supporting observations, previous-check comparisons, and individual recheck buttons. AI can help explain the collected case.

It does not automatically alter Windows settings. It is not an antivirus replacement, a malware-removal tool, or proof that all software is patched. Unsupported or inaccessible values remain unknown.

## 15. Can it combine several scanner reports?

Yes. Supported reports become a common finding format, so the application can show and process evidence from multiple tools.

There is also a duplicate-grouping preview. Its newer repair requires a known matching endpoint/instance and the same complete vulnerability-ID set before grouping records. Missing information is not treated as a match. Alerts that only partly overlap remain separate and visibly linked for review, so one broad alert cannot silently join different weaknesses into a single issue. Original records and the official score queue are preserved. This is still a conservative preview—not independent proof that the tools confirmed the same root cause. Technical section 40.17 records its passing local verification and remaining limits. The report also checks that a supplied grouping preview really matches the current captured assessment, not just a self-consistent file.

The project does not yet have a fully proven AI system that recognises every differently worded duplicate and safely removes it from the official queue. That part needs more implementation and labelled evaluation.

## 16. Can it tell whether a fix worked?

It can compare supplied assessments and classify observations such as still open, new, not observable, fixed candidate, or regression candidate.

An alert disappearing is not enough to prove a fix. The later scanner might have failed or checked something different. The comparison therefore considers coverage and relevant service evidence.

A fixed candidate still needs review. The application does not automatically repair the target or independently certify remediation.

Read the accompanying evidence, not just the label. “Still open” can also mean an earlier alert disappeared but there was not enough evidence to call it fixed. A “regression candidate” can mean newly observed under comparable checks; it does not necessarily mean a previously proven fix has broken again.

## 17. Does everything stay on my computer?

It depends on the selected features.

- Local processing and Ollama can keep analysis on the assessment computer.
- Public intelligence lookups contact the vulnerability publishers.
- A selected cloud model receives the bounded assessment evidence after explicit consent.
- An optional PostgreSQL backend can store records outside the local SQLite file.

Credentials are handled on the server and should remain in ignored environment sources. The browser should not receive the API key.

The application itself binds to the local loopback address. It is not currently a multi-user hosted portal with individual logins and permissions.

There is also a difference between what the code can do and what a particular assessment is permitted to do. The project's standing research rules are stricter than some optional online features. Obtain the relevant approval before sharing assessment evidence with a cloud service; this guide does not grant that permission.

## 18. What is saved?

Depending on the workflow, the project saves database records, scanner artifacts, evidence manifests, assessment checkpoints, AI outcomes, and report exports.

Saved assessments distinguish historical evidence from a new scan. Integrity hashes help detect changed artifacts, although they do not prevent someone with enough local access from replacing both a file and its hash.

Saved replay now uses recorded dates rather than the file's modification date. If an old capture has no recorded date, the app says the date is unknown. Several undated captures cannot be presented as a trustworthy “newest scan.” New records keep collection time separate from later intelligence refresh and AI analysis. A recorded date helps trace the result; it is not independent proof of who performed the scan.

A GitHub push saves tracked project files. Local databases, environment secrets, generated reports, and raw runtime data are normally ignored, so they need a separate backup when required.

## 19. How are we proving the project is useful?

The project contains research tooling to compare its priorities with independent expert judgments.

It can prepare blinded evidence for experts, measure ranking agreement, examine the top findings, and calculate how much of a queue must be reviewed to include all expert-critical items. It can also compare the full method with versions that remove context or threat information.

The learned role classifier has training and evaluation tools as well. These tools need real labels and careful separation of training and evaluation examples.

The important distinction is that an evaluation system exists, while successful real-world results still need to be established. We should not claim “better than experts” or “95% accurate” simply because tests pass.

## 20. How tested is the code?

The latest completed local checkpoint passed **4,194 tests and 525 subtests**, with no failures or skips. Code-style and type checks also passed. Python statement coverage was **99.33%**. The command, output and limits are in [technical-reference section 40.24](TECHNICAL_PROJECT_REFERENCE.md#4024-minimal-website-metadata-and-whole-tree-verification). This includes explanation/history repairs and a privacy-focused HTTP follow-up. It does not prove a complete live assessment or model accuracy. The 95% requirement was not reduced.

In simple terms, the automated tests exercised most of the measured Python code and found no failing tests in that checkpoint. Many tests replace scanners, publishers, or models with controlled substitutes. That tests how the app handles those responses; it does not prove the actual service is available today.

**This is not a claim of 99.33% vulnerability detection or a finished project.** Coverage does not measure real-world detection accuracy, every browser interaction, or whether all planned capabilities exist. Real scanner checks, model comparisons, and expert studies need separate evidence. The technical reference keeps the historical results and earlier failures so they are not confused with the latest checkpoint.

An approved HTTP follow-up can now explain response-header observations, cookie protection attributes and redirect characteristics without saving cookie values, redirect URLs or page bodies. These observations apply to that one literal-IP response, not every page or the site's HTTPS configuration. They can inform cited advice but do not automatically become vulnerabilities or change risk scores. This is not an automatic crawl added to every quick scan.

A repaired research issue allowed owner-supplied exposure information to count as inference with no manual tags. The guard detects that use, keeps the descriptive measurements, and withholds an automatic-inference pass. Saved research artifacts also receive stronger consistency checks. The complete local gate for that earlier repair passed. Further review found a different gap: an older, internally consistent evaluation could attach after profiles changed under the same run ID. Internal consistency alone did not prove that the report and evaluation described the same state. The newer follow-up is explained below; independent real-world context accuracy and the wider audit remain unfinished.

The newer repair now checks that report relationship: changed sources, incompatible predictions and unreconcilable host subsets are rejected. A compatible old evaluation without an input binding keeps its measurements but is visibly marked unbound; it is not presented as verified correspondence to the current assessment. A supplied snapshot binding must match freshly checked state. This follow-up passed its focused checks and the earlier 2,934-test complete gate recorded in technical section 40.14. It still does not prove who supplied the truth or that the research method is accurate in the real world.

Further testing found that a research manifest could quietly convert the wrong kind of value into an accepted one—for example, schema version `1.9` into `1`. The repair rejects those mismatches instead of silently correcting them. It also gives a controlled error for malformed reviewer details, rather than crashing or presenting partial success. Its focused checks and the latest complete gate pass. A typed reviewer name is still not proof that an independent reviewer approved anything.

An independent read-only review then found two more cases that the earlier tests missed: unusual multiline target names could disguise owner-supplied context, and a report snapshot could hide a contradictory model identity. Both now have repairs and regression cases. That earlier increment passed its focused checks and the 3,059-test complete gate in technical section 40.16, adding 125 cases at that point. The independent reviewer found the original defects; that is not an independent approval of the repairs or a security certification. These examples are why a green test suite is evidence to build on, not permission to declare every capability finished.

A later boundary review found that a saved assessment could have a valid hash
but invalid records inside it. The newer checks reject duplicate identities,
records attached to the wrong finding or host, and incorrect value types instead
of quietly converting them. The model-approval file reader also rejects ambiguous
or excessively large JSON before interpreting an approval declaration. Neither a
hash nor a well-formed reviewer name proves that a real independent person
approved the data. Technical section 40.18 records both focused tests and the
complete passing check. The first full attempt failed four existing remediation
tests: unclear old range-boundary hints must stay unknown rather than imply a safe
upgrade. That safe behaviour was restored without changing those existing tests;
strict imported-snapshot checks and score/provenance checks remain in place.

The next repair checks agreement between records, not just whether each record
looks valid. A score cannot select another finding's CVE or contradict the
intelligence and context it claims to use. Missing old input metadata remains
unknown; no score is silently replaced. The file reader now enforces its limit
on the bytes actually read, even if the file changes after the size check, and
rejects numeric overflow anywhere in the JSON. These checks still do not prove
that a capture is genuine or that the risk formula is effective in practice.

The newest follow-up also repeats supported numerical calculations using the
retained inputs and the existing scorer. A report now has a separate **score
arithmetic** row: it distinguishes a completed replay from missing history,
unsupported calculations or no numerical findings. A correct file hash alone
does not give that row a pass. Existing scores are not silently changed to make
them agree, and replay does not turn synthetic data into a real capture. This
checks reproducibility by the current code, not independent proof that the
formula is correct or useful. Historical policies and CVSS 4.0 arithmetic remain
unverified where the required implementation or retained inputs are absent.

A further repair checks inputs before a priority is ever issued, not only when
the report is saved. A malformed role, a text value pretending to be a yes/no
control, invalid manual criticality or another machine's context is rejected.
Another finding's vulnerability information cannot silently supply the score.
Corrupt saved context produces an actionable error instead of a traceback;
rejection leaves the existing ranked list and evidence unchanged. The formula
itself has not changed. Its new focused tests pass; the complete-check result for
this later edit passed and is recorded in technical section 40.21. The app was
also started and opened in the real local browser: its saved overview and workflow
navigation worked, showing two services and zero findings. No fresh scan, model
analysis or live intelligence fetch was claimed by that interface check.

The next explanation repair distinguishes correct-looking text from supported
text. Knowing that a CVE appears in a retained CISA catalogue does not prove
that this machine is being attacked now. An unknown control does not mean no
protection exists, and a high EPSS percentile is not that percentage chance of
exploitation. The rationale-only rewriter now accepts bounded fact-preserving
sentences and requires a full supporting quote for each fact used. Unsupported
wording falls back with Needs review; scores do not change. This is not a claim
that all AI prose or historical explanations have been semantically verified.
The dedicated and complete offline tests pass; technical sections 40.22-40.23
record their results and the separate real-model evaluation still required.

The browser had a separate state bug: Refresh could say stored assessment while
still showing simulated completed steps. That display switch is repaired and
checked in the real browser. It does not finish the product integration: older
saved captures lack reliable times, cannot always be selected for replay, and
do not appear in the newer saved-review list. Live files, database assessments
and printable reports are not yet one continuous workflow. Those are open gaps,
not proof that the scanner found nothing or that an AI model failed.

One required development feature is still missing: the pre-commit hook
configuration and its runner are absent. The local test gate is not proof that
those hooks exist. Neither they nor real-scanner evidence were fabricated to
make the project appear complete.

There was also an execution deviation: the installed Python type-checker wrapper
attempted an unexpected online version lookup during a parallel task. No package
was installed. That was reported, and the gate now uses only its
already-installed checker with a network-denying guard. Earlier passing test
counts remain real, but the test socket guard alone did not establish that this
separate updater was offline. This correction is part of the verification record,
not a security guarantee for every process on the computer.

No real scan or AI-provider call was used to prepare these guides. Later source changes need their own checks.

## 21. What is included now, and what remains?

Implemented capabilities include authorised evidence collection/import, shared records, intelligence integration, rule-based context, deterministic priorities, structured AI analysis, approved AI plans/probes, retained assessments, Windows self-defence, reports, and research tooling.

Still incomplete or unproven are richer context reasoning, semantic merging, independent critic agents, full multi-sample checking, a substantial cited retrieval system, complete installed-software assessment, and independently measured improvements on a representative real dataset.

Some features are intentionally previews or candidates: learned roles, duplicate grouping, and re-scan conclusions should be presented according to those limits.

Recent uncommitted repairs address old unrelated CVEs appearing in a freshly reviewed case, replay marking stages complete without the required retained data, requested scanner failures receiving a generic “complete” summary, port conventions being mistaken for observed protocols, missing severity appearing as Low risk, and copied files receiving misleading capture dates. A partial scan keeps useful evidence while disclosing failed checks. These are specific repairs, not a reason to declare the entire feature list finished.

## 22. A good demonstration

To explain the project to a reviewer:

1. Identify the authorised target and the exact assessment mode.
2. Show scanner coverage and the original observations.
3. Open a supported finding and its provenance.
4. Show the matching vulnerability intelligence and its date.
5. Explain the inferred role, exposure, and control uncertainty.
6. Open the deterministic score breakdown.
7. Show the AI's cited explanation and verification suggestion.
8. Show coverage gaps and any stages that legitimately did not apply.
9. Reopen the retained assessment to demonstrate traceability.

Use a real labelled capture for claims about real behaviour. Clearly identify synthetic examples, replayed evidence, and previews.

## 23. Useful vocabulary

- **Asset:** the machine or service being assessed.
- **Port:** a numbered network endpoint used by a service.
- **Finding:** a recorded potential weakness with supporting evidence.
- **CVE:** a public identifier for a published vulnerability.
- **CVSS:** a standard way to describe vulnerability severity.
- **EPSS:** exploitation-likelihood information about a CVE.
- **KEV:** CISA's known-exploited vulnerability catalogue.
- **CPE:** a standard product identifier used in matching.
- **Context:** the role, exposure, and relevant circumstances of an asset.
- **Provenance:** where an observation came from.
- **Deterministic:** the same inputs produce the same calculation.
- **Hypothesis:** a possible explanation that still needs verification.
- **Shadow model:** a model whose predictions are inspected without controlling official decisions.
- **Ablation:** an experiment that removes one input to see what difference it makes.
- **Scope:** the configured boundary of permitted assessment targets.
- **Observed:** directly present in the supplied evidence.
- **Inferred:** a conclusion drawn from evidence, rather than directly measured.
- **Unknown:** the available checks did not establish the answer.
- **Needs review:** the AI answer was not accepted for publication; it is not proof that the scanner evidence is useless.
- **Not applicable:** this check did not have the inputs or purpose needed for this case; it is different from a check that failed.
- **Unscored:** a finding exists, but the supported inputs were insufficient to justify an official number.
- **Replay:** opening or analysing older evidence without performing a new scan.
- **Mock:** a controlled substitute used in a test, not the actual scanner, publisher, or model.

Two especially important distinctions: “no protection observed” does not mean “no protection exists,” and “no findings recorded” does not mean “safe.”

## 24. A short explanation you can reuse

> VulnAssess is a local-first AI-assisted network vulnerability assessment system. It collects or imports authorised scanner evidence, combines it with vulnerability intelligence and deployment context, calculates transparent priorities, and uses validated AI output to explain findings and suggest verification steps. It preserves supporting evidence and coverage gaps, includes Windows self-defence observations, and provides research tools for evaluating its rankings. Its current results should be understood according to the chosen scan coverage and the evidence actually collected.

For implementation details or questions about a particular claim, continue with the [technical project reference](TECHNICAL_PROJECT_REFERENCE.md).

## 25. How to read a result without being a security expert

Start with six questions, in this order.

### What was checked?

Look for the target, scan time, and coverage. “Top 100 TCP ports” is much narrower than every port, every web page, or every installed application. A saved assessment may show older observations rather than a scan performed today.

### What was actually found?

Services are things that answered, such as a web server. Findings are recorded potential weaknesses. A service is not automatically a vulnerability. Zero findings means the selected checks did not record any; it does not mean the machine has no weaknesses.

### Why is it important here?

Open the context explanation. Check whether the tool inferred a public-facing service, an internal address, a database, or another role. Also check which protections were observed and which remain unknown.

An inference is an estimate with evidence, not something the tool magically knows about the organisation. Business importance may still require an owner's input.

### Where did the number come from?

Open the score breakdown. It should show the vulnerability information, relevant context, threat information, and fixed calculation. AI wording does not create the official number.

The score ranks attention under the project's method. It is not a promise about whether or when an attack will happen.

### What does the AI know, and what is it guessing?

Read the claim label and citation. An observation comes from supplied evidence. An inference interprets evidence. A hypothesis is something to check, not an established finding.

An accepted AI answer passed the implemented checks. A person may still need to decide whether its reasoning is convincing.

### What should happen next?

Use the suggested verification or supported remediation guidance, then confirm the relevant evidence. Unknown authentication might call for checking how access is controlled; it does not justify claiming the service definitely has no password protection.

The app does not automatically apply these changes. Follow-up network requests, when supported, still need approval and must stay within scope.

## 26. Common misunderstandings

**“Every node must run for a successful assessment.”** No. Different tools answer different questions. A web scanner is not useful for a non-web database, and Nessus import needs a report file. The important issue is whether the selected checks covered the intended question and whether failures are clearly shown.

**“NVD, EPSS, and KEV will discover vulnerabilities for us.”** They add facts about identified vulnerabilities. They are not replacements for scanner evidence. Changing the target does not guarantee that all three will have useful data.

**“Local AI analyst always means Ollama.”** Not necessarily. The analyst is the app's analysis feature. It can use Ollama or an explicitly selected supported cloud provider. Check the selected provider and the recorded attempt rather than relying on the node's name.

**“Needs review means the entire scan was wasted.”** No. It means the AI answer was not accepted. Retained observations and deterministic results can still be useful. Separately, an incomplete requested scanner check should be disclosed as incomplete coverage.

**“A fresh AI answer means a fresh scan.”** No. The app can ask a model to explain retained evidence. The scan time, vulnerability-data refresh time, and AI response time are different.

**“The project uses AI, so the AI should set the severity.”** No. The design deliberately keeps official arithmetic reproducible. AI adds interpretation and proposals without becoming the authority for scores or scan permission.

**“100% coverage means 100% complete.”** No. It describes which Python statements ran in a particular test run. It does not measure the number of real vulnerabilities found, current provider reliability, or whether all planned features exist.

**“Pushing everything to GitHub saves every local result.”** No. Code and tracked project files are saved; ignored databases, raw captures, generated output, and secrets are normally not. Sensitive runtime backups need separate handling.

## 27. How to introduce the project to another person

Explain the outcome before listing the tools:

> We are building a network vulnerability assessment system that makes its priorities explainable. It combines authorised scanner observations with vulnerability intelligence and the machine's context, then uses checked AI output to help people understand the results and decide what to verify next.

Then show one finding from beginning to end: original observation, vulnerability facts, context, score calculation, AI citation, and next step. Explain what was not checked. Use Self-defence as a separate example of understanding the local computer's protection settings.

Finish with the honest project status: the core assessment paths exist, several advanced features are bounded previews, specific status/freshness defects have regression-tested repairs, and the research claims still need independent real-world evidence. That is a more useful account than presenting every visible feature as finished.

## 28. Which assessment mode should someone choose?

Choose based on the question, not the number of coloured boxes it will light up.

- **“What is visible on a machine I own or am authorised to test?”** Use an authorised new assessment. Check which ports and tools it actually covers. The usual light Nmap path is a starting point, not an exhaustive assessment.
- **“I already have scanner reports.”** Import the supported reports for the correct target. A completed Nessus export can add evidence without pretending that VulnAssess launched Nessus.
- **“Explain the evidence we collected earlier.”** Use saved review or reanalysis. It should say that the observations are historical; a new AI response does not make the scan new.
- **“Have protection settings on this Windows computer changed?”** Use Self-defence and its individual rechecks. They inspect the computer running the application, not any visitor's laptop.
- **“Did a fix appear to work?”** Compare suitable before/after evidence. Treat a fixed candidate as a reviewable conclusion, not a repair certificate.
- **“Can we prove our ranking is useful?”** Use the research workflow with independently supplied expert judgments. A demonstration website cannot supply those judgments for us.

The workflow includes several specialised tools because assessments differ. There is no single target that can honestly demonstrate a Windows firewall check, Redis behaviour, a web scan, an imported Nessus report, and independent expert evaluation all at once.

## 29. What would a trustworthy result look like?

A useful result lets someone complete this sentence:

> We checked **this target**, using **these checks**, at **this recorded time**. We observed **these services and findings**. These dated sources support **these vulnerability facts**. This context and calculation explain **these priorities**. The AI adds **this checked interpretation**. We still do not know **these things**, so our next step is **this specific verification**.

You should be able to inspect the evidence behind the important parts of that sentence.

A result is less trustworthy when it:

- Says “safe” simply because a limited scan found nothing.
- Calls skipped or failed stages executed.
- Shows an unexplained Low priority when severity information is unavailable.
- Says data are fresh without separating scan time, intelligence time, and analysis time.
- Cites an observation but makes a stronger claim than that observation supports.
- Treats a login page as proof that every relevant operation requires authentication.
- Treats two similar alerts as duplicates without preserving their original evidence.
- Claims improved accuracy without independent labels and a clear comparison.

These are useful review questions even when the application accepts an answer. Automated validation and human judgment have different jobs.

## 30. What has the project added beyond a basic scanner?

A basic scan answers part of “what responded?” or “what did this scanner flag?” VulnAssess has additional implemented layers:

- **A shared evidence format:** different supported scanners feed the same host, service, and finding records.
- **Vulnerability intelligence:** a supported CVE can be connected to severity, exploitation-likelihood information, and known-exploited status.
- **Deployment context:** role, exposure, and observed protection signals are shown with confidence and evidence rather than silently assumed.
- **Transparent priorities:** fixed arithmetic records why a finding moved in the queue.
- **Checked AI interpretation:** the model explains a bounded case and suggests verification without controlling scope or official scores.
- **Limited AI proposals:** supported scan plans and follow-up observations need human approval before execution.
- **Traceability:** original evidence, dates, hashes, saved outcomes, and coverage help reviewers reconstruct what happened.
- **A separate self-check experience:** Windows protection observations are translated into understandable precautions.
- **Research infrastructure:** snapshots, expert comparisons, and controlled experiments help test whether the approach is actually useful.

What has **not** been established is equally important: a fully autonomous security analyst, complete coverage of every device, a proven semantic duplicate-removal system, a production multi-agent debate, a complete advisory-retrieval system, or independently demonstrated gains on a representative real dataset.

The best short description is therefore **an evidence-centred, AI-assisted assessment system with transparent prioritisation**, not “Nmap with every feature finished” and not “AI that decides whether a network is secure.”

For a developer taking the project forward, the [technical reference](TECHNICAL_PROJECT_REFERENCE.md) includes source navigation, stage prerequisites, exact quality-check results, unresolved defects, and a release-readiness checklist.
