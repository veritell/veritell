"use strict";

// Every value from the API is written with textContent only. Nothing from
// the data is ever parsed as markup. Sizes are set through the CSSOM
// (element.style), which the page's policy allows; no style attributes.

const CLASSES = ["human", "verified_bot", "signed_agent", "unverified_agent", "automated", "malicious"];
const KNOWN_CLASSES = new Set(CLASSES);
const AGENT_CLASSES = ["verified_bot", "signed_agent", "unverified_agent"];
const REFRESH_MS = 5000;
const EVENT_LIMIT = 100;
const COLUMNS = 10;
const MAX_CHIPS = 2;

const el = (id) => document.getElementById(id);
const liveEl = el("live");
const statusEl = el("status");
const pauseBox = el("pause");
const filterForm = el("filters");
const windowGroup = el("window");
const eventsBody = el("events");
const histogramEl = el("histogram");
const evictedEl = el("evicted");
const clearBtn = el("clear-filters");
const detectionInput = el("detection");
const siteSelect = el("site");

const numberFormat = new Intl.NumberFormat();
const timeFormat = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dateFormat = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });

// ---------- Site ----------
// One gateway can serve several sites. The chosen one scopes the summary and
// the events, and is kept in the address (#site=...) so a link opens on it.

function currentSite() {
  return siteSelect.value;
}

function siteFromHash() {
  const match = /^#site=(.*)$/.exec(location.hash);
  if (!match) {
    return "";
  }
  try {
    return decodeURIComponent(match[1]).trim().toLowerCase();
  } catch {
    return "";
  }
}

function setSite(site) {
  ensureSiteOption(site);
  siteSelect.value = site;
  const hash = site ? "#site=" + encodeURIComponent(site) : "";
  if (location.hash !== hash) {
    history.replaceState(null, "", location.pathname + location.search + hash);
  }
  siteSelect.parentElement.classList.toggle("active", site !== "");
  document.title = site ? site + " · Veritell" : "Veritell";
}

function ensureSiteOption(site) {
  if (site && ![...siteSelect.options].some((o) => o.value === site)) {
    siteSelect.appendChild(make("option", site)).value = site;
  }
}

// The picker lists every site the gateway served in the window, most
// requests first, and keeps the chosen one even when it has none.
let siteOptionsKey = "";

function renderSiteOptions(byHost) {
  const chosen = currentSite();
  // Rebuilt only when the list changes, so an open picker is not closed by
  // the refresh every few seconds.
  const key = JSON.stringify([byHost, chosen]);
  if (key === siteOptionsKey) {
    return;
  }
  siteOptionsKey = key;
  siteSelect.replaceChildren(make("option", "All sites"));
  siteSelect.options[0].value = "";
  for (const [name, count] of byHost) {
    const option = make("option", String(name) + "  (" + fmt(count) + ")");
    option.value = String(name);
    siteSelect.appendChild(option);
  }
  ensureSiteOption(chosen);
  siteSelect.value = chosen;
}

function pickSite(name) {
  setSite(currentSite() === name ? "" : name);
  refresh();
}

// Keys of the event rows whose details panel is open. Kept across refreshes.
const openKeys = new Set();
let requestSeq = 0;
let debounceTimer = null;
let lastOk = null;

function make(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) {
    node.textContent = String(text);
  }
  if (className) {
    // Callers pass one or more space-separated class names.
    node.classList.add(...String(className).split(" ").filter(Boolean));
  }
  return node;
}

function show(value) {
  if (value === undefined || value === null || value === "") {
    return "–";
  }
  return String(value);
}

function fmt(n) {
  return numberFormat.format(Number(n) || 0);
}

function pct(part, whole) {
  if (!whole || !part) {
    return "0%";
  }
  const p = (100 * part) / whole;
  if (p > 0 && p < 0.1) {
    return "<0.1%";
  }
  return (p < 10 ? p.toFixed(1) : Math.round(p).toString()) + "%";
}

// Visual bands only, for colour: low scores look like bots, high like people.
// The policy's own thresholds decide the action, not these.
function scoreBand(score) {
  const s = Number(score);
  if (Number.isNaN(s)) {
    return "";
  }
  if (s < 30) {
    return "band-low";
  }
  return s < 70 ? "band-mid" : "band-high";
}

function classKey(name) {
  return KNOWN_CLASSES.has(name) ? name : "unknown";
}

// The longest window the gateway answers for (MAX_WINDOW_SECS): 30 days,
// everything it keeps. "All" asks for exactly this.
const MAX_WINDOW_SECS = 30 * 86400;
const customFields = el("window-custom-fields");
const customN = el("window-n");
const customUnit = el("window-unit");

function windowSecs() {
  const checked = windowGroup.querySelector("input:checked");
  if (!checked) {
    return "3600";
  }
  if (checked.value !== "custom") {
    return checked.value;
  }
  const n = Math.floor(Number(customN.value));
  const unit = Number(customUnit.value);
  if (!(n >= 1) || !(unit > 0)) {
    return "3600";
  }
  return String(Math.min(n * unit, MAX_WINDOW_SECS));
}

function windowLabel() {
  const secs = Number(windowSecs());
  if (secs >= MAX_WINDOW_SECS) {
    return "everything kept (30 days)";
  }
  const parts = [[86400, "day"], [3600, "hour"], [60, "minute"]];
  for (const [size, name] of parts) {
    if (secs >= size && secs % size === 0) {
      const n = secs / size;
      return n === 1 ? "last " + name : "last " + n + " " + name + "s";
    }
  }
  return "last " + secs + " seconds";
}

function syncCustomFields() {
  const custom = el("window-custom").checked;
  customFields.hidden = !custom;
}

function setLive(state, message) {
  liveEl.dataset.state = state;
  statusEl.textContent = message;
}

function updateLive() {
  if (liveEl.dataset.state === "error") {
    return;
  }
  if (pauseBox.checked) {
    setLive("paused", lastOk ? "Paused · " + timeFormat.format(lastOk) : "Paused");
  } else if (lastOk) {
    setLive("live", "Live · " + timeFormat.format(lastOk));
  }
}

async function getJson(url) {
  const response = await fetch(url, {
    cache: "no-store",
    headers: { accept: "application/json" },
  });
  if (!response.ok) {
    throw new Error("HTTP " + response.status);
  }
  return response.json();
}

function filterValues() {
  return {
    class: el("class").value,
    kind: el("kind").value,
    detection: detectionInput.value.trim(),
    ip: el("ip").value.trim(),
    max_score: el("max-score").value.trim(),
  };
}

function eventsUrl() {
  const params = new URLSearchParams();
  params.set("limit", String(EVENT_LIMIT));
  if (currentSite()) {
    params.set("host", currentSite());
  }
  for (const [key, value] of Object.entries(filterValues())) {
    if (value !== "") {
      params.set(key, value);
    }
  }
  return "/api/events?" + params.toString();
}

function summaryUrl() {
  const params = new URLSearchParams();
  params.set("window_secs", windowSecs());
  if (currentSite()) {
    params.set("host", currentSite());
  }
  return "/api/summary?" + params.toString();
}

function hasFilters() {
  return Object.values(filterValues()).some((v) => v !== "");
}

// ---------- Summary ----------

function setKpi(id, value, sub) {
  el(id).textContent = fmt(value);
  el(id + "-sub").textContent = sub;
}

function renderKpis(total, byClass) {
  el("total").textContent = fmt(total);
  el("total-sub").textContent = windowLabel() + (currentSite() ? " · " + currentSite() : "");

  const human = byClass.human || 0;
  const automated = byClass.automated || 0;
  const malicious = byClass.malicious || 0;
  const agents = AGENT_CLASSES.reduce((sum, c) => sum + (byClass[c] || 0), 0);

  setKpi("kpi-human", human, pct(human, total) + " of requests");
  setKpi("kpi-automated", automated, pct(automated, total) + " of requests");
  const verified = (byClass.verified_bot || 0) + (byClass.signed_agent || 0);
  setKpi("kpi-agents", agents, fmt(verified) + " verified or signed");
  setKpi("kpi-malicious", malicious, pct(malicious, total) + " of requests");
  el("kpi-malicious").classList.toggle("nonzero", malicious > 0);
}

function renderClassBreakdown(total, byClass) {
  const bar = el("class-bar");
  bar.replaceChildren();
  const legend = el("by-class");
  legend.replaceChildren();

  for (const name of CLASSES) {
    const count = byClass[name] || 0;
    if (count > 0) {
      const seg = make("span", null, "seg-" + name);
      seg.style.flexGrow = String(count);
      bar.appendChild(seg);
    }

    const item = make("li", null, count === 0 ? "zero" : "");
    item.appendChild(make("span", null, "dot dot-" + name));
    item.appendChild(make("span", name, "lg-name"));
    item.appendChild(make("span", fmt(count), "lg-count"));
    item.appendChild(make("span", pct(count, total), "lg-pct"));
    legend.appendChild(item);
  }
}

function renderHistogram(buckets) {
  histogramEl.replaceChildren();
  const counts = Array.isArray(buckets) ? buckets.map((n) => Number(n) || 0) : [];
  const max = Math.max(1, ...counts);
  counts.forEach((count, i) => {
    const low = i * 10;
    const col = make("div", null, "hist-col " + scoreBand(low + 5));
    col.title = low + "–" + (i === counts.length - 1 ? "255" : low + 9) + ": " + fmt(count);
    col.appendChild(make("span", count ? fmt(count) : "0", count ? "hist-count" : "hist-count zero"));
    const track = make("div", null, "hist-track");
    const bar = make("div", null, count ? "hist-bar" : "hist-bar zero");
    bar.style.height = count ? Math.max(2, (100 * count) / max) + "%" : "2px";
    track.appendChild(bar);
    col.appendChild(track);
    col.appendChild(make("span", String(low), "hist-label"));
    histogramEl.appendChild(col);
  });
}

function renderRanked(listEl, entries, total, options) {
  listEl.replaceChildren();
  if (entries.length === 0) {
    listEl.appendChild(make("li", "Nothing in this window", "empty"));
    return;
  }
  const max = Math.max(1, ...entries.map(([, c]) => Number(c) || 0));
  const active = options && options.active;
  for (const [name, count] of entries) {
    const item = make("li");
    const fill = make("span", null, "rk-fill");
    fill.style.width = (100 * (Number(count) || 0)) / max + "%";
    item.appendChild(fill);
    item.appendChild(make("span", name, "rk-name"));
    item.appendChild(make("span", fmt(count), "rk-count"));
    item.appendChild(make("span", pct(count, total), "rk-pct"));
    if (options && options.onPick) {
      item.classList.add("clickable");
      item.tabIndex = 0;
      item.title = "Filter events by " + name;
      if (active === name) {
        item.classList.add("active");
      }
      const pick = () => options.onPick(String(name));
      item.addEventListener("click", pick);
      item.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          pick();
        }
      });
    }
    listEl.appendChild(item);
  }
}

function pickDetection(name) {
  detectionInput.value = detectionInput.value.trim() === name ? "" : name;
  refresh();
}

function renderSummary(summary) {
  const total = Number(summary.total ?? 0);
  const byClass = summary.by_class || {};

  renderKpis(total, byClass);
  renderClassBreakdown(total, byClass);
  renderHistogram(summary.score_histogram);

  const top = Array.isArray(summary.top_detections) ? summary.top_detections : [];
  renderRanked(el("top-detections"), top, total, {
    onPick: pickDetection,
    active: detectionInput.value.trim(),
  });

  const byOutcome = Object.entries(summary.by_outcome || {}).sort((a, b) => b[1] - a[1]);
  renderRanked(el("by-outcome"), byOutcome, total);

  const byHost = Array.isArray(summary.by_host) ? summary.by_host : [];
  const allSites = byHost.reduce((sum, [, c]) => sum + (Number(c) || 0), 0);
  renderRanked(el("by-host"), byHost, allSites, { onPick: pickSite, active: currentSite() });
  renderSiteOptions(byHost);

  const evicted = Number(summary.evicted || 0);
  evictedEl.hidden = evicted === 0;
  evictedEl.textContent = evicted === 0
    ? ""
    : fmt(evicted) + " events were discarded to stay within the store's capacity.";
}

// ---------- Events ----------

function outcomeClass(outcome) {
  const o = String(outcome || "").toLowerCase();
  if (o === "passed" || o === "solved" || o === "valid") {
    return "outcome oc-good";
  }
  if (o.includes("fail") || o.includes("block") || o.includes("deny")) {
    return "outcome oc-bad";
  }
  return "outcome";
}

function reasonsTable(detections) {
  const wrap = make("div", null, "table-wrap");
  const table = make("table", null, "reasons");
  const thead = make("thead");
  const headRow = make("tr");
  for (const heading of ["Detection", "Layer", "Penalty", "Explanation"]) {
    const th = make("th", heading);
    th.setAttribute("scope", "col");
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = make("tbody");
  for (const d of detections) {
    const row = make("tr");
    row.appendChild(make("td", show(d.id), "mono"));
    row.appendChild(make("td", show(d.layer)));
    row.appendChild(make("td", "−" + show(d.penalty), "penalty"));
    row.appendChild(make("td", show(d.detail)));
    tbody.appendChild(row);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

function buildDetails(ev) {
  const panel = make("div", null, "why");

  const reasons = make("div", null, "why-block");
  reasons.appendChild(make("h3", "Reasons"));
  const detections = Array.isArray(ev.detections) ? ev.detections : [];
  if (detections.length === 0) {
    reasons.appendChild(make("p", "No detections contributed to this decision.", "muted"));
  } else {
    reasons.appendChild(reasonsTable(detections));
  }
  panel.appendChild(reasons);

  const factsBlock = make("div", null, "why-block");
  factsBlock.appendChild(make("h3", "Request and decision"));
  const facts = [
    ["Enforced", ev.enforced ? "yes" : "no (shadow)"],
    ["Action", ev.action],
    ["Outcome", ev.outcome],
    ["Score", ev.score],
    ["Route", ev.route],
    ["Rule", ev.rule],
    ["Token", ev.token],
    ["Identity", ev.identity],
    ["Known person", ev.known],
    ["Host", ev.host],
    ["Method", ev.method],
    ["Path", ev.path],
    ["ASN", ev.asn],
    ["Network class", ev.net_class],
    ["User-Agent", ev.user_agent],
    ["JA4", ev.ja4],
    ["HTTP/2", ev.h2],
    // Logged, never scored. The TTL is as it arrived, after the hops.
    ["TCP SYN", ev.tcp ? ev.tcp + " (TTL " + ev.tcp_ttl + ")" : ""],
  ];
  const list = make("dl", null, "facts");
  for (const [label, value] of facts) {
    const text = show(value);
    list.appendChild(make("dt", label));
    list.appendChild(make("dd", text, text === "–" ? "empty" : ""));
  }
  factsBlock.appendChild(list);
  panel.appendChild(factsBlock);
  return panel;
}

function eventKey(ev) {
  return JSON.stringify([ev.ts_ms, ev.ip, ev.method, ev.path, ev.user_agent, ev.kind]);
}

function setOpen(row, details, key, open) {
  if (open) {
    openKeys.add(key);
  } else {
    openKeys.delete(key);
  }
  details.hidden = !open;
  row.setAttribute("aria-expanded", open ? "true" : "false");
}

function timeCell(ms) {
  const cell = make("td", null, "t-time");
  const date = new Date(Number(ms));
  if (Number.isNaN(date.getTime())) {
    cell.textContent = "–";
    return cell;
  }
  cell.title = date.toLocaleString();
  cell.appendChild(make("span", timeFormat.format(date)));
  cell.appendChild(make("span", dateFormat.format(date), "t-date"));
  return cell;
}

function scoreCell(score) {
  const cell = make("td", null, "t-score num");
  const wrap = make("span", null, "score");
  const meter = make("span", null, "score-meter " + scoreBand(score));
  const fill = make("span");
  fill.style.width = Math.max(0, Math.min(100, Number(score) || 0)) + "%";
  meter.appendChild(fill);
  wrap.appendChild(meter);
  wrap.appendChild(make("span", show(score)));
  cell.appendChild(wrap);
  return cell;
}

function detectionsCell(detections) {
  const cell = make("td");
  if (detections.length === 0) {
    cell.appendChild(make("span", "–", "muted"));
    return cell;
  }
  const chips = make("div", null, "chips");
  for (const d of detections.slice(0, MAX_CHIPS)) {
    chips.appendChild(make("span", show(d.id), "chip"));
  }
  if (detections.length > MAX_CHIPS) {
    const more = make("span", "+" + (detections.length - MAX_CHIPS), "chip chip-more");
    more.title = detections.slice(MAX_CHIPS).map((d) => show(d.id)).join(", ");
    chips.appendChild(more);
  }
  cell.appendChild(chips);
  return cell;
}

function renderEvents(events) {
  eventsBody.replaceChildren();
  const count = el("events-count");
  count.textContent = events.length === 0
    ? "no matches"
    : (events.length >= EVENT_LIMIT ? "latest " : "") + fmt(events.length) + (events.length === 1 ? " event" : " events");
  clearBtn.hidden = !hasFilters();

  if (events.length === 0) {
    const row = make("tr");
    const cell = make("td", hasFilters() ? "No events match these filters." : "No events yet.", "empty-cell");
    cell.colSpan = COLUMNS;
    row.appendChild(cell);
    eventsBody.appendChild(row);
    return;
  }

  for (const ev of events) {
    const key = eventKey(ev);
    const row = make("tr", null, "event");
    row.tabIndex = 0;
    const detections = Array.isArray(ev.detections) ? ev.detections : [];

    const chev = make("td");
    chev.appendChild(make("span", null, "chev"));
    row.appendChild(chev);

    row.appendChild(timeCell(ev.ts_ms));
    row.appendChild(make("td", show(ev.kind), "t-kind"));

    const client = make("td", null, "t-client");
    const ip = make("span", show(ev.ip), "mono");
    ip.title = show(ev.ip);
    client.appendChild(ip);
    row.appendChild(client);

    const req = make("td", null, "t-req");
    if (ev.host) {
      const host = make("span", show(ev.host), "host");
      host.title = "Show only " + show(ev.host);
      host.addEventListener("click", (event) => {
        event.stopPropagation();
        pickSite(String(ev.host).toLowerCase());
      });
      req.appendChild(host);
    }
    const reqWrap = make("div", null, "req");
    reqWrap.appendChild(make("span", show(ev.method), "method"));
    const path = make("span", show(ev.path), "path");
    path.title = show(ev.host) + show(ev.path);
    reqWrap.appendChild(path);
    req.appendChild(reqWrap);
    row.appendChild(req);

    row.appendChild(scoreCell(ev.score));

    const classCell = make("td");
    classCell.appendChild(make("span", show(ev.class), "badge cls-" + classKey(ev.class)));
    row.appendChild(classCell);

    const actionCell = make("td");
    const action = show(ev.action);
    actionCell.appendChild(make("span", action, action === "pass" ? "action pass" : "action"));
    if (ev.enforced === false && action !== "pass") {
      const tag = make("span", "shadow", "shadow-tag");
      tag.title = "Not enforced: the gateway is in shadow mode for this decision";
      actionCell.appendChild(tag);
    }
    row.appendChild(actionCell);

    const outcomeCell = make("td");
    outcomeCell.appendChild(make("span", show(ev.outcome), outcomeClass(ev.outcome)));
    row.appendChild(outcomeCell);

    row.appendChild(detectionsCell(detections));

    const details = make("tr", null, "details");
    const cell = make("td");
    cell.colSpan = COLUMNS;
    cell.appendChild(buildDetails(ev));
    details.appendChild(cell);

    setOpen(row, details, key, openKeys.has(key));

    const toggle = () => setOpen(row, details, key, details.hidden);
    row.addEventListener("click", toggle);
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        toggle();
      }
    });

    eventsBody.appendChild(row);
    eventsBody.appendChild(details);
  }
}

// ---------- Refresh loop ----------

async function refresh() {
  const seq = ++requestSeq;
  try {
    const [summary, events] = await Promise.all([
      getJson(summaryUrl()),
      getJson(eventsUrl()),
    ]);
    if (seq !== requestSeq) {
      return;
    }
    renderSummary(summary);
    renderEvents(Array.isArray(events) ? events : []);
    lastOk = new Date();
    liveEl.dataset.state = "live";
    updateLive();
  } catch (err) {
    if (seq !== requestSeq) {
      return;
    }
    const reason = err && err.message ? err.message : "request failed";
    setLive("error", "Refresh failed (" + reason + "), retrying");
  }
}

function scheduleRefresh() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(refresh, 300);
}

filterForm.addEventListener("submit", (event) => {
  event.preventDefault();
  refresh();
});
filterForm.addEventListener("input", scheduleRefresh);
filterForm.addEventListener("change", scheduleRefresh);
windowGroup.addEventListener("change", () => {
  syncCustomFields();
  refresh();
});
customN.addEventListener("change", refresh);
customUnit.addEventListener("change", refresh);
siteSelect.addEventListener("change", () => {
  setSite(currentSite());
  refresh();
});
window.addEventListener("hashchange", () => {
  setSite(siteFromHash());
  refresh();
});

clearBtn.addEventListener("click", () => {
  filterForm.reset();
  refresh();
});

pauseBox.addEventListener("change", () => {
  if (pauseBox.checked) {
    updateLive();
  } else {
    refresh();
  }
});

setInterval(() => {
  if (!pauseBox.checked) {
    refresh();
  }
}, REFRESH_MS);

setSite(siteFromHash());
refresh();
