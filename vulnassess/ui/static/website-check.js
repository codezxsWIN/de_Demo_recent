const byId = (id) => document.getElementById(id);
let report = null;
function list(id, items) {
  const nodes = items.map((text) => {
    const li = document.createElement("li");
    li.textContent = text;
    return li;
  });
  byId(id).replaceChildren(...nodes);
}
byId("website-start").addEventListener("click", async () => {
  const status = byId("website-status");
  if (!byId("website-consent").checked) {
    status.textContent = "Confirm the metadata-only check before continuing.";
    return;
  }
  report = null;
  byId("website-report").hidden = true;
  byId("website-evidence").replaceChildren();
  byId("website-start").disabled = true;
  status.textContent = "Checking public destinations, then requesting bounded root metadata…";
  try {
    const response = await fetch("/api/public-website/check", {
      method: "POST", cache: "no-store", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-VulnAssess-Action": "public-website" },
      body: JSON.stringify({ target: byId("website-target").value.trim(), confirm_metadata_only: true }),
      signal: AbortSignal.timeout(15000),
    });
    const value = await response.json();
    if (!response.ok) throw new Error(value.error?.message || "Website check could not complete.");
    if (value.schema_version !== "public_website.v1" || !Array.isArray(value.evidence)) {
      throw new Error("Website report format is not recognised. No results shown.");
    }
    report = value;
    byId("website-result-heading").textContent = value.state === "complete" ? "Metadata collected — not a safety verdict" : "Incomplete check — coverage limited";
    byId("website-summary").textContent = `${value.origin} · ${value.checked_at} · ${value.state}${value.path_discarded ? " · Submitted page path discarded; root only." : ""}`;
    const nodes = value.evidence.map((item) => {
      const block = document.createElement("article");
      block.className = "evidence";
      const tag = document.createElement("small");
      tag.textContent = `${item.id} / ${item.label}`;
      const text = document.createElement("p");
      text.textContent = item.text;
      block.append(tag, text);
      return block;
    });
    byId("website-evidence").replaceChildren(...nodes);
    list("website-precautions", value.precautions);
    list("website-coverage", [
      `Executed: ${value.coverage.executed.join("; ")}`,
      `Not run: ${value.coverage.not_run.join("; ")}`,
      ...value.coverage.limitations,
    ]);
    byId("website-report").hidden = false;
    status.textContent = value.failure || "Metadata check complete. Evidence and limitations are shown below.";
  } catch (error) {
    report = null;
    byId("website-report").hidden = true;
    status.textContent = error instanceof Error ? error.message : "Website check unavailable.";
  } finally {
    byId("website-start").disabled = false;
  }
});
byId("website-download").addEventListener("click", () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "VulnAssess-public-website-metadata.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
