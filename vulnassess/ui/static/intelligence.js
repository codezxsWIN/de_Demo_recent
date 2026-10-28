const element = (id) => document.getElementById(id);
const number = (value) => value == null ? "Not cached" : Number(value).toLocaleString(undefined, { maximumFractionDigits: 4 });
const percent = (value) => value == null ? "Not cached" : `${(value * 100).toFixed(2)}%`;
const node = (tag, text, className) => {
  const result = document.createElement(tag);
  if (text != null) result.textContent = text;
  if (className) result.className = className;
  return result;
};
let page = 1;
let active = null;
let detailRequest = null;
let pagination = null;
const initial = new URLSearchParams(location.search);
element("search").value = initial.get("q") || "";
if (["all", "nvd", "epss", "kev"].includes(initial.get("source"))) element("source").value = initial.get("source");
if (["25", "50", "100"].includes(initial.get("page_size"))) element("page-size").value = initial.get("page_size");
if (/^[1-9][0-9]{0,5}$/.test(initial.get("page") || "")) page = Number(initial.get("page"));

function renderSources(sources) {
  element("sources").replaceChildren();
  for (const [name, source] of Object.entries(sources)) {
    const card = node("article", null, "source");
    card.append(node("h3", name === "kev" ? "CISA KEV" : name.toUpperCase()));
    card.append(node("p", `${number(source.stored_rows)} stored records · ${source.source_kind} · ${source.status}`));
    card.append(node("p", source.coverage));
    card.append(node("p", `${source.date_label}: ${source.reference_date || "Not recorded"}`));
    card.append(node("p", `Loaded: ${source.loaded_at || "Not recorded"}`));
    card.append(node("p", `Source: ${source.path || "Provenance not recorded"}`));
    card.append(node("code", `SHA-256: ${source.sha256 || "Not recorded"}`));
    element("sources").append(card);
  }
}

async function details(cve) {
  detailRequest?.abort();
  const controller = new AbortController();
  detailRequest = controller;
  element("detail-title").textContent = cve;
  element("detail-body").textContent = "";
  element("detail-status").textContent = "Reading cached publisher details…";
  element("detail").showModal();
  try {
    const response = await fetch(`/api/intelligence?cve=${encodeURIComponent(cve)}`, { signal: controller.signal });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error?.message || "Cached details are unavailable");
    if (controller.signal.aborted) return;
    element("detail-status").textContent = `${result.state} · ${result.notice}`;
    const preview = JSON.stringify({ record: result.record, sources: result.sources }, null, 2);
    element("detail-body").textContent = preview.length > 65536 ? `${preview.slice(0, 65536)}\n[Detail preview limited to 65,536 characters]` : preview;
  } catch (error) {
    if (error.name !== "AbortError") element("detail-status").textContent = error.message;
  }
}

function renderRecords(records) {
  element("records").replaceChildren();
  for (const record of records) {
    const row = node("tr");
    const identity = node("td");
    identity.append(node("strong", record.cve));
    identity.append(node("small", record.description || record.kev_name || "NVD description not cached; reference record available from the listed sources."));
    if (record.summary_unavailable.length) identity.append(node("small", `Summary unavailable: ${record.summary_unavailable.join(", ")}. Open cached details for the source record.`));
    const scores = node("td");
    scores.append(node("span", record.cvss31_base == null ? "3.1: not cached" : `3.1: ${number(record.cvss31_base)}`));
    scores.append(node("small", record.cvss40_base == null ? "4.0: not cached" : `4.0: ${number(record.cvss40_base)}`));
    const epss = node("td", percent(record.epss));
    epss.append(node("small", `Percentile: ${percent(record.epss_percentile)}`));
    epss.append(node("small", `Score date: ${record.epss_date || "Not cached"}`));
    const kev = node("td", record.kev_listed == null ? "Not checked" : record.kev_listed ? "Listed in cached KEV" : "No cached KEV record");
    if (record.kev_listed) {
      kev.append(node("small", `Added: ${record.kev_date_added || "Not recorded"}`));
      kev.append(node("small", `Due date: ${record.kev_due_date || "Not recorded"}`));
    }
    const action = node("td");
    const button = node("button", "View details");
    button.type = "button";
    button.setAttribute("aria-label", `View cached details for ${record.cve}`);
    button.addEventListener("click", () => details(record.cve));
    action.append(button);
    row.append(identity, node("td", record.sources.map((source) => source.toUpperCase()).join(" · ")), scores, epss, kev, action);
    element("records").append(row);
  }
}

async function load() {
  active?.abort();
  const controller = new AbortController();
  active = controller;
  pagination = null;
  element("previous").disabled = true;
  element("next").disabled = true;
  element("status").textContent = "Reading local intelligence…";
  element("records").replaceChildren();
  const query = new URLSearchParams({ page, page_size: element("page-size").value, source: element("source").value, q: element("search").value.trim() });
  try {
    const response = await fetch(`/api/intelligence/catalog?${query}`, { signal: controller.signal });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error?.message || "The catalog is unavailable");
    if (controller.signal.aborted) return;
    history.replaceState(null, "", `/intelligence?${query}`);
    element("boundary").textContent = result.notice;
    element("counts").replaceChildren();
    for (const [key, label] of Object.entries({ total: "Unique CVE identifiers", nvd: "NVD detail records", epss: "EPSS score records", kev: "KEV catalog records" })) {
      const card = node("div", null, "count");
      card.append(node("strong", number(result.counts[key])), node("span", label));
      element("counts").append(card);
    }
    renderSources(result.sources);
    renderRecords(result.records);
    pagination = result.pagination;
    element("previous").disabled = !pagination.has_previous;
    element("next").disabled = !pagination.has_next;
    const states = {
      missing: "No intelligence cache found. Import public intelligence to populate this catalog.",
      not_cached: "A local sibling intelligence cache is not configured for this database.",
      fixture: "Test fixture data detected. Reference records are hidden; these counts are not operational publisher coverage.",
      unavailable: "The intelligence cache could not be read. No publisher coverage is claimed.",
      empty: "The local intelligence cache contains no reference records.",
    };
    element("status").textContent = states[result.state] || `${number(pagination.total_records)} matching identifiers · ${number(pagination.returned)} shown. Search matches a literal CVE prefix.`;
    element("page-label").textContent = pagination.total_pages ? `Page ${page.toLocaleString()} of ${number(pagination.total_pages)}` : "No matching records";
  } catch (error) {
    if (error.name !== "AbortError") {
      element("status").textContent = error.message;
      element("counts").replaceChildren();
      element("sources").replaceChildren();
      element("page-label").textContent = "Catalog unavailable";
    }
  }
}

element("filters").addEventListener("submit", (event) => { event.preventDefault(); page = 1; load(); });
element("refresh").addEventListener("click", () => load());
element("previous").addEventListener("click", () => { if (pagination?.has_previous) { page -= 1; load(); } });
element("next").addEventListener("click", () => { if (pagination?.has_next) { page += 1; load(); } });
element("close-detail").addEventListener("click", () => element("detail").close());
element("detail").addEventListener("close", () => detailRequest?.abort());
load();
