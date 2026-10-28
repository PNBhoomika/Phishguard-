let latestResult = null;

function decisionClass(decision) {
  return decision === "PHISHING" ? "critical" : decision === "SUSPICIOUS" ? "suspicious" : decision === "SAFE" ? "low-risk" : "pending";
}

function renderList(selector, items, emptyText) {
  const list = document.querySelector(selector);
  list.replaceChildren();
  if (!items?.length) {
    const row = document.createElement("li");
    row.textContent = emptyText;
    list.append(row);
    return;
  }
  for (const item of items) {
    const row = document.createElement("li");
    row.textContent = typeof item === "string" ? item : JSON.stringify(item);
    list.append(row);
  }
}

function displayResult(result) {
  if (!result) return;
  latestResult = result;
  document.querySelector("#emptyState").classList.add("hidden");
  document.querySelector("#result").classList.remove("hidden");

  const decision = result.decision || "SCANNING";
  const level = document.querySelector("#riskLevel");
  level.textContent = decision;
  level.className = `level ${decisionClass(decision)}`;
  document.querySelector("#score").innerHTML = `${Number.isFinite(result.fused) ? result.fused : "—"}<small>/100</small>`;
  document.querySelector("#meterFill").style.width = `${Number.isFinite(result.fused) ? result.fused : 0}%`;
  document.querySelector("#meterFill").className = decisionClass(decision);
  document.querySelector("#host").textContent = result.url || "Current tab";
  document.querySelector("#summary").textContent = result.status === "complete"
    ? `Scan complete · Updated ${new Date(result.timestamps?.updatedAt || Date.now()).toLocaleTimeString()}`
    : result.extremeBlock ? "Extreme-confidence URL signal: warning shown while the DOM report completes."
      : "URL checked; waiting for page structure analysis. The page remains usable while the scan runs.";
  document.querySelector("#mlScore").textContent = result.mlAvailable && Number.isFinite(result.mlScore) ? `${Math.round(result.mlScore)}/100` : "Unavailable";
  document.querySelector("#heuristicScore").textContent = Number.isFinite(result.urlHeurScore) ? `${result.urlHeurScore}/100` : "—";
  document.querySelector("#domScore").textContent = Number.isFinite(result.domScore) ? `${result.domScore}/100` : "Pending";
  document.querySelector("#modelStatus").textContent = result.mlAvailable ? "Model loaded" : "Model unavailable — using heuristic+DOM fusion";
  document.querySelector("#extremeConfidence").textContent = result.extremeConfidence ? "Yes" : "No";

  renderList("#findings", result.findings, "No findings recorded.");
  renderList("#appliedRules", result.appliedRules, "No fusion overrides applied.");
}

async function getResult(tabId) {
  return chrome.runtime.sendMessage({ type: "PHISHGUARD_GET_RESULT", tabId });
}

async function loadActiveTab(rescan = false) {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (!tab?.id || !/^https?:/.test(tab.url || "")) {
    document.querySelector("#scanStatus").textContent = "This page cannot be scanned";
    return;
  }

  let result = rescan
    ? await chrome.runtime.sendMessage({ type: "PHISHGUARD_SCAN_TAB", tabId: tab.id })
    : await getResult(tab.id);
  if (!result) result = await chrome.runtime.sendMessage({ type: "PHISHGUARD_SCAN_TAB", tabId: tab.id });
  displayResult(result);

  for (let attempt = 0; attempt < 10 && result?.status !== "complete"; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 400));
    result = await getResult(tab.id);
    if (result) displayResult(result);
  }
}

document.querySelector("#scan").addEventListener("click", () => loadActiveTab(true));
document.querySelector("#copyReport").addEventListener("click", async () => {
  if (!latestResult) return;
  await navigator.clipboard.writeText(JSON.stringify(latestResult, null, 2));
  document.querySelector("#copyReport").textContent = "JSON report copied";
});

void loadActiveTab();
