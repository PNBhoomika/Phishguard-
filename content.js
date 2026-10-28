/*
 * Privacy contract: inspect page structure and form destinations only.
 * Never read input values, submit forms, or send page text/content anywhere.
 */
"use strict";

(() => {
  if (globalThis.__phishGuardDomScannerInstalled) {
    globalThis.__phishGuardScheduleProbe?.(true);
    return;
  }
  globalThis.__phishGuardDomScannerInstalled = true;

  const MAX_SCORE = 100;
  const RESCAN_INTERVAL_MS = 2000;
  let scanId = null;
  let probeTimer = null;
  let fullScanTimer = null;
  let lastProbeSignature = "";
  let lastFullScanAt = 0;
  let lastFullSignature = "";
  let observer = null;

  function pageForms() {
    const forms = [...document.forms];
    for (const frame of document.querySelectorAll("iframe")) {
      try { forms.push(...(frame.contentDocument?.forms || [])); } catch { /* Cross-origin frames are inaccessible. */ }
    }
    return [...new Set(forms)];
  }

  function pagePasswordFields() {
    const fields = [...document.querySelectorAll('input[type="password"]')];
    for (const frame of document.querySelectorAll("iframe")) {
      try { fields.push(...(frame.contentDocument?.querySelectorAll('input[type="password"]') || [])); } catch { /* Cross-origin frames are inaccessible. */ }
    }
    return [...new Set(fields)];
  }

  function hiddenCredentialInputs() {
    const inputs = [...document.querySelectorAll('input[type="hidden"]')];
    for (const frame of document.querySelectorAll("iframe")) {
      try { inputs.push(...(frame.contentDocument?.querySelectorAll('input[type="hidden"]') || [])); } catch { /* Cross-origin frames are inaccessible. */ }
    }
    return [...new Set(inputs)].filter((input) => /pass(word)?|credential|secret/i.test(`${input.name} ${input.id}`));
  }

  function probePage() {
    const pageOrigin = location.origin;
    const forms = pageForms();
    const formActionOrigins = [...new Set(forms.map((form) => {
      const baseUrl = form.ownerDocument?.location?.href || location.href;
      const action = form.getAttribute("action") || baseUrl;
      try { return new URL(action, baseUrl).origin; } catch { return "invalid"; }
    }))];
    return {
      hasPasswordField: pagePasswordFields().length > 0 || hiddenCredentialInputs().length > 0,
      hasForm: forms.length > 0,
      formActionOrigins,
      hasCrossOriginForm: formActionOrigins.some((origin) => origin !== pageOrigin)
    };
  }

  function scanDom() {
    const findings = [];
    const pageUrl = new URL(location.href);
    const forms = pageForms();
    const passwordFields = pagePasswordFields();

    for (const form of forms) {
      const baseUrl = form.ownerDocument?.location?.href || location.href;
      const action = form.getAttribute("action") || baseUrl;
      let target;
      try { target = new URL(action, baseUrl); } catch { continue; }
      const containsPassword = Boolean(form.querySelector('input[type="password"]'));
      if (containsPassword && target.origin !== pageUrl.origin) findings.push("password_form_cross_origin");
      if (containsPassword && target.protocol !== "https:") findings.push("password_form_http");
      if (!containsPassword && target.origin !== pageUrl.origin && target.protocol === "http:") findings.push("external_form_http");
    }

    const hiddenPasswordFields = passwordFields.filter((field) => {
      const style = getComputedStyle(field);
      return style.display === "none" || style.visibility === "hidden" || field.getClientRects().length === 0;
    }).concat(hiddenCredentialInputs());
    if (hiddenPasswordFields.length) findings.push("hidden_password_field");

    const hiddenIframesWithForms = [...document.querySelectorAll("iframe")].some((frame) => {
      const style = getComputedStyle(frame);
      const hidden = style.display === "none" || style.visibility === "hidden" || frame.getClientRects().length === 0;
      if (!hidden) return false;
      try { return Boolean(frame.contentDocument?.forms.length); } catch { return false; }
    });
    if (hiddenIframesWithForms || ([...document.querySelectorAll("iframe")].some((frame) => {
      const style = getComputedStyle(frame);
      return (style.display === "none" || style.visibility === "hidden" || frame.getClientRects().length === 0) && forms.length > 0;
    }))) findings.push("hidden_iframe_with_form");

    if (passwordFields.length > 0 && forms.length === 0) findings.push("password_field_without_form");

    const points = {
      password_form_cross_origin: 35,
      password_form_http: 35,
      external_form_http: 15,
      hidden_password_field: 20,
      hidden_iframe_with_form: 10,
      password_field_without_form: 5
    };
    const domScore = Math.max(0, Math.min(MAX_SCORE, findings.reduce((total, id) => total + points[id], 0)));
    return { domScore, findings: [...new Set(findings)] };
  }

  function send(type, payload) {
    chrome.runtime.sendMessage({ type, url: location.href, scanId, ...payload }).catch(() => {});
  }

  function runFullScan() {
    const now = Date.now();
    const wait = lastFullScanAt + RESCAN_INTERVAL_MS - now;
    if (wait > 0) {
      if (!fullScanTimer) fullScanTimer = setTimeout(() => {
        fullScanTimer = null;
        runFullScan();
      }, wait);
      return;
    }
    const result = scanDom();
    const signature = `${location.href}|${JSON.stringify(result)}`;
    lastFullScanAt = now;
    if (signature === lastFullSignature) return;
    lastFullSignature = signature;
    send("PHISHGUARD_DOM_RESULT", result);
  }

  function runProbe(force = false) {
    const probe = probePage();
    const signature = `${location.href}|${JSON.stringify(probe)}`;
    if (!force && signature === lastProbeSignature) return;
    lastProbeSignature = signature;
    send("PHISHGUARD_DOM_PROBE_RESULT", { probe });
  }

  function scheduleProbe(force = false) {
    clearTimeout(probeTimer);
    if (force) {
      lastProbeSignature = "";
      lastFullSignature = "";
    }
    probeTimer = setTimeout(() => runProbe(force), 50);
  }

  globalThis.__phishGuardScheduleProbe = scheduleProbe;

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "PHISHGUARD_SCAN_INIT") {
      if (scanId !== message.scanId) {
        clearTimeout(fullScanTimer);
        fullScanTimer = null;
        lastFullScanAt = 0;
        lastFullSignature = "";
      }
      scanId = message.scanId;
      scheduleProbe(true);
    } else if (message?.type === "PHISHGUARD_RUN_DOM_SCAN") {
      if (message.scanId === scanId) runFullScan();
    }
  });

  function nodeHasSensitiveStructure(node) {
    if (!(node instanceof Element)) return false;
    return node.matches("form, input, iframe") || Boolean(node.querySelector("form, input, iframe"));
  }

  function mutationAffectsStructure(record) {
    if (record.type === "attributes") {
      return record.target instanceof Element && record.target.matches("form, input, iframe");
    }
    if (record.target instanceof Element && record.target.closest("form")) return true;
    return [...record.addedNodes, ...record.removedNodes].some(nodeHasSensitiveStructure);
  }

  function inspectAfterMutation() {
    scheduleProbe(true);
  }

  function ready() {
    scheduleProbe(true);
    observer = new MutationObserver((records) => {
      if (records.some(mutationAffectsStructure)) inspectAfterMutation();
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["type", "action", "style", "class"]
    });
    setTimeout(() => observer?.disconnect(), 30000);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", ready, { once: true });
  else ready();
})();
