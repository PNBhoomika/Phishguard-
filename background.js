"use strict";

importScripts("rules.js", "ml/inference.js", "hybrid.js");

const currentScans = new Map();
const storageWrites = new Map();
const DOM_PROBE_TIMEOUT_MS = 1800;
const PAGE_LOAD_WAIT_MS = 900;
const modelReady = PhishGuardML.preloadModel();

function storageKey(tabId) {
  return `scan:${tabId}`;
}

function isWebUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function decisionRank(decision) {
  return ({ SAFE: 0, SUSPICIOUS: 1, PHISHING: 2 })[decision] ?? -1;
}

function findingText(finding) {
  return typeof finding === "string" ? finding : `${finding.id}: ${finding.title} — ${finding.detail}`;
}

function createReport(state, overrides = {}) {
  const report = {
    url: state.url,
    scanId: state.scanId,
    decision: null,
    fused: null,
    mlScore: null,
    urlHeurScore: null,
    domScore: null,
    mlAvailable: false,
    hardExtreme: false,
    softExtreme: false,
    extremeConfidence: false,
    findings: [],
    appliedRules: [],
    timestamps: { startedAt: state.startedAt, updatedAt: new Date().toISOString() },
    status: "scanning_url",
    urlResult: state.urlResult || null,
    lockedPhishing: Boolean(state.lockedPhishing),
    ...overrides
  };
  return report;
}

async function saveReport(tabId, state, overrides = {}) {
  const report = createReport(state, overrides);
  currentScans.set(tabId, { ...state, report });
  await persistReport(tabId, report);
  return report;
}

function persistReport(tabId, report) {
  const previous = storageWrites.get(tabId) || Promise.resolve();
  const current = previous.catch(() => {}).then(() => chrome.storage.session.set({ [storageKey(tabId)]: report }));
  storageWrites.set(tabId, current);
  current.then(() => {
    if (storageWrites.get(tabId) === current) storageWrites.delete(tabId);
  }, () => {
    if (storageWrites.get(tabId) === current) storageWrites.delete(tabId);
  });
  return current;
}

async function getState(tabId) {
  const memoryState = currentScans.get(tabId);
  if (memoryState) return memoryState;
  const stored = (await chrome.storage.session.get(storageKey(tabId)))[storageKey(tabId)];
  if (!stored) return null;
  const state = {
    scanId: stored.scanId,
    url: stored.url,
    startedAt: stored.timestamps?.startedAt || new Date().toISOString(),
    urlResult: stored.urlResult || null,
    lockedPhishing: Boolean(stored.lockedPhishing),
    priorDecision: stored.decision || null,
    report: stored
  };
  currentScans.set(tabId, state);
  return state;
}

async function warnTab(tabId, report) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (data) => {
        if (location.href !== data.url) return;
        const id = "__phishguard_warning__";
        document.getElementById(id)?.remove();
        const host = document.createElement("div");
        host.id = id;
        host.style.cssText = "all:initial;position:fixed;inset:0 0 auto 0;z-index:2147483647";
        const shadow = host.attachShadow({ mode: "closed" });
        const style = document.createElement("style");
        style.textContent = `:host{all:initial}.bar{font:15px/1.45 system-ui,sans-serif;color:#fff;padding:15px 20px;box-shadow:0 4px 18px #0006;display:flex;gap:18px;align-items:center;justify-content:space-between}.phishing{background:#7f1d1d}.suspicious{background:#81530b}.copy{max-width:760px}strong{font-size:17px}.actions{display:flex;gap:8px;flex-shrink:0}button{font:600 14px system-ui;border:0;border-radius:6px;padding:9px 13px;cursor:pointer}.back{background:#fff;color:#362100}.dismiss{background:#402b0b;color:#fff;border:1px solid #d99}`;
        const bar = document.createElement("div");
        bar.className = `bar ${data.decision === "PHISHING" ? "phishing" : "suspicious"}`;
        const copy = document.createElement("div");
        copy.className = "copy";
        const title = document.createElement("strong");
        title.textContent = data.decision === "PHISHING" ? `PhishGuard: PHISHING · ${data.fused}/100` : `PhishGuard: SUSPICIOUS · ${data.fused}/100`;
        const detail = document.createElement("div");
        detail.textContent = data.decision === "PHISHING"
          ? "This page has strong phishing indicators. Do not enter passwords, payment details, or verification codes."
          : "PhishGuard: This page shows some risk signals. Do not enter credentials until verified.";
        copy.append(title, detail);
        const actions = document.createElement("div");
        actions.className = "actions";
        const back = document.createElement("button");
        back.className = "back";
        back.textContent = "Go back";
        back.addEventListener("click", () => history.length > 1 ? history.back() : host.remove());
        const dismiss = document.createElement("button");
        dismiss.className = "dismiss";
        dismiss.textContent = "Dismiss";
        dismiss.addEventListener("click", () => host.remove());
        actions.append(back, dismiss);
        bar.append(copy, actions);
        shadow.append(style, bar);
        (document.documentElement || document).append(host);
      },
      args: [report]
    });
  } catch (error) {
    console.warn("PhishGuard could not show the page warning:", error.message);
  }
}

async function clearWarning(tabId, expectedUrl) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (url) => {
        if (url && location.href !== url) return;
        document.getElementById("__phishguard_warning__")?.remove();
      },
      args: [expectedUrl]
    });
  } catch {
    // Browser-internal pages do not allow extension script injection.
  }
}

async function showDecision(tabId, report, previousDecision) {
  const decision = report.decision;
  if (decisionRank(previousDecision) > decisionRank(decision)) return;
  if (decision === "SAFE") await clearWarning(tabId, report.url);
  else await warnTab(tabId, report);
}

async function requestDomProbe(tabId, state, forceDomScan, waitForLoad) {
  try {
    if (waitForLoad) await waitForPageIdle(tabId);
    if (currentScans.get(tabId)?.scanId !== state.scanId) return;
    await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
    await chrome.tabs.sendMessage(tabId, {
      type: "PHISHGUARD_SCAN_INIT",
      scanId: state.scanId,
      forceDomScan
    });
    setTimeout(() => {
      void (async () => {
        const current = await getState(tabId);
        if (current?.scanId !== state.scanId || current.report?.status !== "awaiting_dom_probe") return;
        await finishDomScan(tabId, current, { domScore: 0, findings: [] });
      })();
    }, DOM_PROBE_TIMEOUT_MS);
  } catch (error) {
    console.warn("PhishGuard could not start the page scan:", error.message);
    await finishDomScan(tabId, state, { domScore: 0, findings: [] });
  }
}

async function waitForPageIdle(tabId) {
  const tab = await chrome.tabs.get(tabId);
  if (tab.status === "complete") return;
  await new Promise((resolve) => {
    let finished = false;
    let timer;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      chrome.tabs.onUpdated.removeListener(onUpdated);
      resolve();
    };
    const onUpdated = (updatedTabId, changeInfo) => {
      if (updatedTabId === tabId && changeInfo.status === "complete") finish();
    };
    timer = setTimeout(finish, PAGE_LOAD_WAIT_MS);
    chrome.tabs.onUpdated.addListener(onUpdated);
  });
}

async function startScan(tabId, url, newNavigation = true, waitForLoad = false, clearExistingBanner = false) {
  if (!isWebUrl(url)) return;
  const previousState = newNavigation ? null : await getState(tabId);
  const reusableState = previousState?.url === url ? previousState : null;
  const scanId = reusableState?.scanId || `${Date.now()}:${crypto.randomUUID()}`;
  const priorDecision = reusableState?.report?.decision || null;
  const priorFused = reusableState?.report?.fused ?? null;
  const lockedPhishing = reusableState?.report?.decision === "PHISHING";
  const state = {
    scanId,
    url,
    startedAt: reusableState?.startedAt || new Date().toISOString(),
    priorDecision,
    lockedPhishing,
    urlResult: null,
    report: null
  };
  currentScans.set(tabId, state);
  if (clearExistingBanner || (!reusableState && !waitForLoad)) await clearWarning(tabId, url);
  await saveReport(tabId, state, {
    decision: priorDecision,
    fused: priorFused,
    mlScore: reusableState?.report?.mlScore ?? null,
    urlHeurScore: reusableState?.report?.urlHeurScore ?? null,
    domScore: reusableState?.report?.domScore ?? null,
    findings: reusableState?.report?.findings || [],
    appliedRules: reusableState?.report?.appliedRules || [],
    mlAvailable: reusableState?.report?.mlAvailable ?? false,
    extremeConfidence: reusableState?.report?.extremeConfidence ?? false,
    lockedPhishing,
    status: "scanning_url",
    mlAvailable: false
  });
  if (currentScans.get(tabId)?.scanId !== scanId) return;

  try {
    const quickHeuristic = PhishGuardRules.scoreUrl(url);
    const quickHeurScore = PhishGuardHybrid.clampScore(quickHeuristic.score);
    const hardExtreme = Boolean(quickHeuristic.hardExtreme);
    const softExtreme = Boolean(quickHeuristic.softExtreme);
    const quickExtremeBlock = hardExtreme || (softExtreme && quickHeurScore >= 40);
    const prewarnedExtreme = quickExtremeBlock && !lockedPhishing;
    if (prewarnedExtreme) {
      const quickUrlResult = {
        url: quickHeuristic.url,
        valid: quickHeuristic.valid,
        hostname: quickHeuristic.hostname,
        mlScore: null,
        mlAvailable: false,
        urlHeurScore: quickHeurScore,
        extremeConfidence: true,
        urlFindings: quickHeuristic.findings || [],
        featureSummary: quickHeuristic.featureSummary || null
      };
      state.urlResult = quickUrlResult;
      const immediate = PhishGuardHybrid.fuse({
        mlAvailable: false,
        urlHeurScore: quickHeurScore,
        domScore: 0,
        hardExtreme,
        softExtreme,
        extremeConfidence: hardExtreme || softExtreme
      });
      state.report = createReport(state, {
        ...immediate,
        fused: Math.max(80, immediate.fused),
        decision: "PHISHING",
        mlAvailable: false,
        hardExtreme,
        softExtreme,
        extremeConfidence: true,
        urlHeurScore: quickHeurScore,
        urlResult: quickUrlResult,
        urlFindings: quickUrlResult.urlFindings.map(findingText),
        findings: quickUrlResult.urlFindings.map(findingText),
        appliedRules: immediate.appliedRules,
        status: "scanning_url",
        extremeBlock: true,
        lockedPhishing: true
      });
      state.lockedPhishing = true;
      state.priorDecision = "PHISHING";
      currentScans.set(tabId, state);
      await persistReport(tabId, state.report);
      if (currentScans.get(tabId)?.scanId !== scanId) return;
      await warnTab(tabId, state.report);
    }

    await modelReady;
    if (currentScans.get(tabId)?.scanId !== scanId) return;
    const urlResult = await PhishGuardHybrid.analyseUrl(url);
    state.urlResult = urlResult;
    const extremeBlock = Boolean(urlResult.hardExtreme || (urlResult.softExtreme && urlResult.urlHeurScore >= 40));
    const urlFindings = urlResult.urlFindings.map(findingText);
    const urlStageFusion = PhishGuardHybrid.fuse({
      mlScore: urlResult.mlScore,
      mlAvailable: urlResult.mlAvailable,
      urlHeurScore: urlResult.urlHeurScore,
      domScore: 0,
    });
    const urlPreview = PhishGuardHybrid.fuseUrlStage({
      mlScore: urlResult.mlScore,
      mlAvailable: urlResult.mlAvailable,
      urlHeurScore: urlResult.urlHeurScore
    });

    const report = createReport(state, {
      mlScore: urlResult.mlScore,
      urlHeurScore: urlResult.urlHeurScore,
      domScore: null,
      mlAvailable: urlResult.mlAvailable,
      hardExtreme: urlResult.hardExtreme,
      softExtreme: urlResult.softExtreme,
      extremeConfidence: urlResult.extremeConfidence,
      urlResult,
      lockedPhishing: lockedPhishing || extremeBlock,
      findings: urlFindings,
      urlFindings,
      domFindings: [],
      appliedRules: [...new Set([
        ...(extremeBlock ? urlStageFusion.appliedRules : urlPreview.appliedRules),
        ...(priorDecision === "PHISHING" ? state.report?.appliedRules || [] : [])
      ])],
      status: "awaiting_dom_probe",
      decision: extremeBlock ? "PHISHING" : priorDecision || (urlPreview.fused >= 35 && urlPreview.fused < 50 ? "SUSPICIOUS" : null),
      fused: extremeBlock ? Math.max(80, urlStageFusion.fused, priorFused || 0) : Math.max(priorFused || 0, urlPreview.fused),
      lockedPhishing: lockedPhishing || extremeBlock,
      extremeBlock
    });

    state.report = report;
    currentScans.set(tabId, state);
    await persistReport(tabId, report);
    if (currentScans.get(tabId)?.scanId !== scanId) return;
    if (extremeBlock || report.decision === "SUSPICIOUS") await warnTab(tabId, report);
    if (currentScans.get(tabId)?.scanId !== scanId) return;
    await requestDomProbe(tabId, state, extremeBlock, waitForLoad);
  } catch (error) {
    console.warn("PhishGuard URL scan failed:", error.message);
    if (currentScans.get(tabId)?.scanId === scanId) await finishDomScan(tabId, state, { domScore: 0, findings: [] });
  }
}

async function finishDomScan(tabId, state, domResult) {
  const current = await getState(tabId);
  if (!current || current.scanId !== state.scanId || current.url !== state.url || !current.urlResult) return;
  const previousDecision = current.report?.decision || current.priorDecision || null;
  const normalizedDOM = {
    domScore: PhishGuardHybrid.clampScore(domResult.domScore),
    findings: Array.isArray(domResult.findings) ? domResult.findings.map(String) : []
  };
  if (previousDecision && previousDecision !== "SAFE") {
    normalizedDOM.domScore = Math.max(normalizedDOM.domScore, current.report?.domScore || 0);
    normalizedDOM.findings = [...new Set([...(current.report?.domFindings || []), ...normalizedDOM.findings])];
  }
  const fused = PhishGuardHybrid.combineWithDom(current.urlResult, normalizedDOM, previousDecision);
  if (current.report?.extremeBlock) {
    fused.decision = "PHISHING";
    fused.fused = Math.max(80, fused.fused);
    if (!fused.appliedRules.includes("extreme_confidence_url_block")) fused.appliedRules.push("extreme_confidence_url_block");
  } else if (previousDecision === "PHISHING") {
    fused.decision = "PHISHING";
    fused.fused = Math.max(current.report?.fused || 50, fused.fused);
    if (!fused.appliedRules.includes("navigation_decision_no_downgrade")) fused.appliedRules.push("navigation_decision_no_downgrade");
  } else if (previousDecision === "SUSPICIOUS") {
    fused.decision = "SUSPICIOUS";
    fused.fused = Math.max(PhishGuardHybrid.SAFE_THRESHOLD, current.report?.fused || 0, fused.fused);
    if (!fused.appliedRules.includes("navigation_decision_no_downgrade")) fused.appliedRules.push("navigation_decision_no_downgrade");
  }

  const urlFindings = current.urlResult.urlFindings.map(findingText);
  const report = createReport(current, {
    fused: fused.fused,
    decision: fused.decision,
    mlScore: current.urlResult.mlScore,
    urlHeurScore: current.urlResult.urlHeurScore,
    domScore: normalizedDOM.domScore,
    mlAvailable: current.urlResult.mlAvailable,
    extremeConfidence: current.urlResult.extremeConfidence,
    hardExtreme: current.urlResult.hardExtreme,
    softExtreme: current.urlResult.softExtreme,
    findings: [...urlFindings, ...normalizedDOM.findings],
    urlFindings,
    domFindings: normalizedDOM.findings,
    appliedRules: [...new Set([...(current.report?.appliedRules || []), ...fused.appliedRules])],
    status: "complete",
    extremeBlock: Boolean(current.report?.extremeBlock),
    lockedPhishing: fused.decision === "PHISHING"
  });
  state.report = report;
  state.priorDecision = fused.decision;
  state.lockedPhishing = fused.decision === "PHISHING";
  currentScans.set(tabId, state);
  await persistReport(tabId, report);
  if (currentScans.get(tabId)?.scanId !== state.scanId) return;
  await showDecision(tabId, report, previousDecision);
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0) void startScan(details.tabId, details.url, true, true);
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId === 0) void startScan(details.tabId, details.url, true, false, true);
});

chrome.webNavigation.onReferenceFragmentUpdated.addListener((details) => {
  if (details.frameId === 0) void startScan(details.tabId, details.url, true, false, true);
});

async function scanOpenTabs() {
  await modelReady;
  const tabs = await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] });
  for (const tab of tabs) if (tab.id != null && tab.url) void startScan(tab.id, tab.url, true, false, true);
}

chrome.runtime.onInstalled.addListener(() => { void scanOpenTabs(); });
chrome.runtime.onStartup.addListener(() => { void scanOpenTabs(); });

chrome.tabs.onRemoved.addListener((tabId) => {
  currentScans.delete(tabId);
  const previous = storageWrites.get(tabId) || Promise.resolve();
  const removal = previous.catch(() => {}).then(() => chrome.storage.session.remove(storageKey(tabId)));
  storageWrites.set(tabId, removal);
  removal.then(() => {
    if (storageWrites.get(tabId) === removal) storageWrites.delete(tabId);
  }, () => {
    if (storageWrites.get(tabId) === removal) storageWrites.delete(tabId);
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "PHISHGUARD_DOM_PROBE_RESULT") {
    const tabId = sender.tab?.id;
    if (tabId == null || !message.probe) return false;
    void (async () => {
      const state = await getState(tabId);
      if (!state || state.scanId !== message.scanId || state.url !== message.url) {
        sendResponse({ ok: false, stale: true });
        return;
      }
      const probe = message.probe;
      const sensitive = Boolean(probe.hasPasswordField || probe.hasForm || probe.hasCrossOriginForm);
      if (sensitive || state.report?.extremeBlock) {
        await chrome.tabs.sendMessage(tabId, { type: "PHISHGUARD_RUN_DOM_SCAN", scanId: state.scanId });
      } else {
        await finishDomScan(tabId, state, { domScore: 0, findings: [] });
      }
      sendResponse({ ok: true, sensitive });
    })().catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "PHISHGUARD_DOM_RESULT") {
    const tabId = sender.tab?.id;
    if (tabId == null || !message.dom) return false;
    void (async () => {
      const state = await getState(tabId);
      if (!state || state.scanId !== message.scanId || state.url !== message.url) {
        sendResponse({ ok: false, stale: true });
        return;
      }
      const tab = await chrome.tabs.get(tabId);
      if (tab.url !== message.url) {
        sendResponse({ ok: false, stale: true });
        return;
      }
      await finishDomScan(tabId, state, message.dom);
      sendResponse({ ok: true });
    })().catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (message?.type === "PHISHGUARD_GET_RESULT") {
    void chrome.storage.session.get(storageKey(message.tabId)).then((stored) => {
      sendResponse(stored[storageKey(message.tabId)] || null);
    });
    return true;
  }

  if (message?.type === "PHISHGUARD_SCAN_TAB") {
    void chrome.tabs.get(message.tabId).then((tab) => startScan(message.tabId, tab.url, false)).then(() =>
      chrome.storage.session.get(storageKey(message.tabId))
    ).then((stored) => sendResponse(stored[storageKey(message.tabId)] || null)).catch(() => sendResponse(null));
    return true;
  }
  return false;
});
