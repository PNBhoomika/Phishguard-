const input = document.querySelector("#urlInput");
const resultSection = document.querySelector("#result");
let latestResult = null;

function cssLevel(level) { return level.toLowerCase().replace(" ", "-"); }

function displayResult(result) {
  latestResult = result;
  document.querySelector("#emptyState").classList.add("hidden");
  resultSection.classList.remove("hidden");
  const level = document.querySelector("#riskLevel");
  level.textContent = result.level;
  level.className = `level ${cssLevel(result.level)}`;
  document.querySelector("#score").innerHTML = `${result.score}<small>/100</small>`;
  document.querySelector("#meterFill").style.width = `${result.score}%`;
  document.querySelector("#meterFill").className = cssLevel(result.level);
  document.querySelector("#host").textContent = result.valid ? result.hostname : "No analysis available";
  document.querySelector("#summary").textContent = result.valid
    ? result.ml.available ? `Combined score: 60% ML probability and 40% heuristic risk.` : "ML model could not load; showing heuristic score only."
    : result.error;
  document.querySelector("#mlScore").textContent = result.ml.available ? `${result.ml.score}%` : "Unavailable";
  document.querySelector("#heuristicScore").textContent = result.valid ? `${result.heuristic.score}/100` : "—";

  const findings = document.querySelector("#findings");
  findings.replaceChildren();
  for (const finding of result.findings) {
    const row = document.createElement("li");
    row.innerHTML = `<b>+${finding.points}</b><span><strong>${finding.title}</strong>${finding.detail}</span>`;
    findings.append(row);
  }
  if (!result.findings.length && result.valid) findings.innerHTML = "<li><span>No heuristic phishing signals were found.</span></li>";
}

async function scan() {
  const button = document.querySelector("#scan");
  button.disabled = true;
  button.textContent = "Analysing…";
  try { displayResult(await PhishGuardHybrid.analyse(input.value.trim())); }
  finally { button.disabled = false; button.innerHTML = "Scan URL <span>→</span>"; }
}

document.querySelector("#scan").addEventListener("click", scan);
input.addEventListener("keydown", (event) => { if (event.key === "Enter") scan(); });
document.querySelector("#currentTab").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (tab?.url) { input.value = tab.url; scan(); }
});
document.querySelector("#copyReport").addEventListener("click", async () => {
  if (!latestResult?.valid) return;
  const report = ["PhishGuard hybrid risk report", `URL: ${latestResult.url}`, `Final risk: ${latestResult.level} (${latestResult.score}/100)`, `ML phishing probability: ${latestResult.ml.available ? `${latestResult.ml.score}%` : "unavailable"}`, `Heuristic score: ${latestResult.heuristic.score}/100`, "", ...latestResult.findings.map((item) => `+${item.points}: ${item.title} — ${item.detail}`)].join("\n");
  await navigator.clipboard.writeText(report);
  document.querySelector("#copyReport").textContent = "Report copied";
});
