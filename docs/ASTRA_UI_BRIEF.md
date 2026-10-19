# VulnAssess UI Challenge for GPT-6 Astra

You are redesigning the real VulnAssess interface. This is not a detached mockup,
marketing landing page, or fictional cybersecurity dashboard. Inspect the repository,
run the current application, understand the stored assessment contract, and then make
the working product unusually clear, memorable, and polished.

The standard is not "good for a student project." The standard is a product that a
technical evaluator remembers after reviewing several competing projects.

## Mission

Create a punchy first-screen experience and a radically more comprehensible workflow
experience for VulnAssess.

Within the first five seconds, a new evaluator should understand:

1. VulnAssess begins with authorized scanner evidence.
2. It adds threat intelligence and network context.
3. It calculates a deterministic, inspectable priority.
4. Its local AI analyst is advisory and must cite stored evidence.
5. The same vulnerability can deserve different urgency on different targets.

The interface must feel authored for this specific research system. It must not resemble
a generic admin dashboard, template marketplace theme, SOC dashboard, fake terminal, or
AI chat wrapper.

## Read This Repository First

Before changing the interface, inspect these sources as authoritative:

- [`README.md`](../README.md)
- [`docs/ui.md`](ui.md)
- [`docs/ui-contract.md`](ui-contract.md)
- [`docs/DESIGN.md`](DESIGN.md)
- [`docs/methodology.md`](methodology.md)
- [`vulnassess/ui/presentation.py`](../vulnassess/ui/presentation.py)
- [`vulnassess/ui/static/index.html`](../vulnassess/ui/static/index.html)
- [`vulnassess/ui/static/app.js`](../vulnassess/ui/static/app.js)
- [`vulnassess/ui/static/workbench.css`](../vulnassess/ui/static/workbench.css)
- [`vulnassess/ui/static/workflow.html`](../vulnassess/ui/static/workflow.html)
- [`vulnassess/ui/static/workflow.js`](../vulnassess/ui/static/workflow.js)
- [`vulnassess/ui/static/workflow.css`](../vulnassess/ui/static/workflow.css)
- [`tests/test_ui.py`](../tests/test_ui.py)

Run the real UI against the existing `reallab` assessment. Do not design from screenshots
alone. Verify desktop and mobile behavior in a browser before and after implementation.

## Product Truth That Must Survive

VulnAssess is a local-first vulnerability prioritization system. Its canonical priority
is produced by deterministic stored calculations, not by the language model.

The product currently connects:

- Authorized scope and targets
- Nmap ports, services, banners, and findings
- ZAP web application findings
- Nikto web server findings
- Canonical normalized finding records
- NVD CVEs and CVSS vectors
- EPSS exploitation probability
- CISA KEV known-exploitation status
- Evidence-backed role, exposure, and control inference
- CVSS Environmental and threat-informed scoring
- Stored priority order
- Exact explanations and provenance
- Optional local AI target analysis with evidence citations
- Reports, expert evaluation, and rescan comparison when attached

Do not invent evidence, targets, findings, model output, feed freshness, report status, or
pipeline completion. Unknown and missing states must remain visibly honest.

## Curated Visual References

These references are ingredients, not templates. Study both the Awwwards case page and
the live site where available. Extract structural principles, typography, motion, and
interaction behavior. Do not clone their branding.

### 1. Checkpoint Research: Primary Visual Language

- [Awwwards case](https://www.awwwards.com/sites/checkpoint-research)
- [Live site](https://checkpointresearch.ca/)

Study:

- Technical blueprint language
- Confident oversized typography
- Fine grid and measurement details
- Research credibility
- Clear information planes without card soup
- Controlled use of a saturated signal color

Use it to influence the application shell, provenance treatment, evidence labels, section
transitions, and overall visual discipline.

### 2. Rogo: Trustworthy AI Product Behavior

- [Awwwards case](https://www.awwwards.com/sites/rogo)
- [Live site](https://www.rogodata.com/)

Study:

- Secure and professional AI positioning
- Calm control hierarchy
- Clear separation between product action and explanation
- Refined loading, empty, success, and error states
- AI presented as a tool rather than a personality

Use it to influence the local analyst experience. The analyst must feel useful and
expensive without becoming a generic chatbot.

### 3. Bitnomial: Precision Under High Stakes

- [Awwwards case](https://www.awwwards.com/sites/bitnomial)
- [Live site](https://bitnomial.com/)

Study:

- Institutional precision
- Strong numeric typography
- Restrained high-risk accents
- Thin technical linework
- Confidence without visual noise
- Presentation of regulated, consequential information

Use it to influence risk values, score formation, severity, comparisons, and status.

### 4. L.I.S.A.: Transformational Interaction

- [Awwwards case](https://www.awwwards.com/sites/l-i-s-a)
- [Live site](https://lisa.locomotive.ca/en)

Study:

- Progressive disclosure
- Conversational microcopy
- Transitions that transform one information state into another
- Responsive interaction choreography
- Evidence that an assistant can feel spatial rather than chat-based

Do not copy the avatar, 3D spectacle, agency tone, or experimental navigation. Borrow only
the interaction intelligence.

### 5. Surveillance Watch: Relationship Energy, Not Layout

- [Awwwards case](https://www.awwwards.com/sites/surveillance-watch)
- [Live site](https://surveillancewatch.io/)

Study:

- Connected data as an emotional visual object
- Selection-driven disclosure
- Strong contrast between the field and the selected entity
- How a relationship can be felt before every detail is read

Do not use its full-map experience as the VulnAssess default. It is too visually dominant
and too demanding for routine assessment work.

### 6. WISPR Flow: Motion-Led Product Explanation

- [Awwwards case](https://www.awwwards.com/sites/wispr-flow)
- [Live site](https://wisprflow.ai/)

Study its state transitions and product demonstrations. Do not copy its consumer warmth,
photographic marketing treatment, or landing-page composition.

### 7. ZIRKA Interceptor: Operational Intensity

- [Awwwards case](https://www.awwwards.com/sites/zirka-interceptor)
- [Live site](https://zrk.technology/)

Study the confidence, instrumentation, and status language. Do not copy the military
theme, cinematic 3D, orange campaign palette, or scroll spectacle.

### Reference Collections

- [Awwwards Technology](https://www.awwwards.com/websites/technology/)
- [Awwwards Storytelling](https://www.awwwards.com/websites/storytelling/)
- [Awwwards Data Visualization](https://www.awwwards.com/websites/data-visualization/)
- [Awwwards Interaction Design](https://www.awwwards.com/websites/interaction-design/)

## Creative Challenge

The current workbench opens with a long evidence page. The separate workflow is inspired
by Make.com and displays the full system as a large node canvas. On real data, that graph
becomes too broad to comprehend; fitting it onto a narrow screen makes the nodes too small
to read.

Do not solve this only by adding a minimap, breadcrumbs, more tabs, ordinary collapsible
groups, or extra zoom controls. Those may exist as supporting utilities, but they are not
the concept.

Find a visual idea that makes causality itself memorable.

One promising direction is **TRACEBACK**:

- Start with the final priority decision.
- Let the user travel backward through calculation, context, intelligence, and raw evidence.
- Transform the selected score into its contributing evidence rather than showing every
  system node simultaneously.
- Compress unselected findings into quiet signals or marks.
- Allow two findings to split into synchronized traces so the exact contextual divergence
  becomes visible.
- Let AI citations act as anchors that return the user to their original evidence.

TRACEBACK is a direction, not a mandatory wireframe. If you discover a stronger, equally
implementable concept after inspecting the product, pursue it. The replacement must be
more original than a node graph and easier to understand than the current workflow.

## First-Screen Requirement

The opening viewport must be the real product, not a landing page.

It should make one stored decision immediately legible:

- Selected assessment and whether its evidence is real, synthetic, or unlabelled
- Highest-priority finding
- Target and endpoint
- Stored risk and band
- The shortest honest explanation of why it ranks first
- A visible path back to raw evidence
- An immediate way to inspect the full target or request local AI analysis

Use the actual selected assessment. Never hard-code impressive numbers or fake a critical
finding. If the assessment is empty, show an intentional empty state that explains what
record is missing and how the product becomes populated.

## Visual Direction

Aim for a collision of research publication, forensic instrument, and premium technical
product.

- Cold off-white and true near-black surfaces
- One distinctive navigation signal color
- Semantic risk colors used only for actual status
- Large grotesk display type where conclusions deserve it
- Monospace for evidence, identifiers, vectors, hashes, and provenance
- Sharp grids and fine rules
- Very limited corner radius
- Minimal shadows
- Motion that reveals causality or state change
- A composition with deliberate asymmetry and editorial tension

The interface must remain readable and operational. Visual confidence must come from
hierarchy, typography, rhythm, and behavior rather than decorative effects.

## Do Not Build

- A marketing hero followed by feature sections
- A conventional sidebar plus KPI-card dashboard
- A giant graph as the default first screen
- A purple or blue cyber gradient
- Glassmorphism
- Floating card grids
- A fake terminal
- A chatbot as the main interface
- Decorative 3D or WebGL without an essential explanatory role
- Infinite animation or constantly moving connection lines
- Fake loading delays intended to make the model look more capable
- Draggable nodes or editable connections; this is not a workflow builder
- A redesign that hides raw evidence, provenance, unknown states, or scoring boundaries

## Interaction Principles

1. Every conclusion must offer a path to its source evidence.
2. Selection should reorganize the composition around the user's question.
3. Motion must explain transformation, dependency, comparison, or provenance.
4. The interface should reveal complexity progressively without pretending it does not exist.
5. The selected finding should remain stable while the user moves between views.
6. Filters and navigation state should be reflected in the URL where practical.
7. Keyboard interaction, focus management, and reduced-motion behavior are first-class.
8. Mobile may use a different spatial composition, but it must preserve the same evidence
   and decision model.

## Implementation Boundaries

- Preserve the existing Python application and its read-only UI/API contracts.
- Preserve deterministic scoring and stored priority order.
- Preserve local-only model behavior and citation validation.
- Prefer the existing vanilla HTML, CSS, JavaScript, and SVG stack.
- Do not migrate to React, add Three.js, or introduce a large animation framework merely
  to achieve visual polish.
- Add a dependency only when native browser capabilities cannot reasonably deliver the
  selected concept.
- Use semantic HTML and real buttons, links, labels, headings, tables, and dialogs.
- Maintain or improve the offline export path.
- Do not weaken tests to accommodate the redesign.
- Keep implementation complexity proportional to the explanatory value it creates.

## Required States

Design and implement all of these, not only the ideal populated state:

- Initial loading
- Populated real assessment
- Synthetic assessment
- Unlabelled source
- No runs
- Run unavailable
- No findings
- Unscored finding
- Missing enrichment
- Missing optional scanner import
- Model unavailable
- Model request running
- Model response with valid citations
- Model response rejected for malformed or unknown citations
- Narrow mobile viewport
- Reduced motion
- Keyboard-only navigation

## Acceptance Criteria

The redesign is complete only when all of the following are true:

1. A first-time evaluator can identify the product's purpose and top decision within five
   seconds of the populated UI appearing.
2. The first viewport uses real assessment data and offers a direct route to source evidence.
3. The workflow no longer requires comprehension of all nodes at once.
4. Nmap, ZAP, Nikto, NVD, EPSS, CISA KEV, context inference, scoring, prioritization, local
   analysis, reporting, expert evaluation, and rescan states remain represented honestly.
5. The local analyst cannot visually imply that it owns or changes canonical risk.
6. Raw scanner quotes, feed provenance, configuration identity, and scoring adjustments
   remain inspectable.
7. The interface works without horizontal document overflow at 320, 390, 768, 1024, and
   1440 CSS pixels.
8. Interactive controls have accessible names, visible focus, and logical keyboard order.
9. Reduced-motion users receive an immediate, fully understandable state.
10. Browser console output contains no errors or warnings during core workflows.
11. Existing UI and application tests pass, with focused tests added for new behavior.
12. Final desktop and mobile screenshots show a coherent product, not a compressed desktop
    composition.

## Work Process

1. Run and inspect the existing application with `reallab`.
2. Inventory the facts, interactions, and contracts that cannot be lost.
3. Produce one strong visual thesis, not several half-developed themes.
4. State what each reference contributes and what is deliberately rejected.
5. Implement the first viewport and the new workflow concept in the real application.
6. Exercise populated, missing, loading, error, model, and mobile states.
7. Capture desktop and mobile screenshots.
8. Compare the result against this brief and remove any generic dashboard residue.
9. Run the relevant test suite and report exact verification evidence.

## Final Standard

Be bold in composition and conservative with truth.

The result should make an evaluator think, "I have not seen vulnerability prioritization
explained this way before," while still letting a security practitioner verify every claim.
Do not stop at a polished skin. Redesign how the product reveals causality.
