/* Native JavaScript inference matching the Colab feature extractor exactly. */
(function (root) {
  "use strict";

  const RISKY_TLDS = new Set(["zip", "mov", "click", "top", "xyz", "tk", "gq", "ml", "cf", "work", "country", "rest", "loan", "racing"]);
  const KEYWORDS = ["login", "signin", "verify", "verification", "secure", "update", "account", "wallet", "password", "confirm", "unlock", "payment"];

  function entropy(value) {
    if (!value) return 0;
    const frequency = {};
    for (const character of value) frequency[character] = (frequency[character] || 0) + 1;
    return Object.values(frequency).reduce((total, count) => {
      const probability = count / value.length;
      return total - probability * Math.log2(probability);
    }, 0);
  }

  function isIpAddress(hostname) {
    const ipv4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(hostname);
    return ipv4 || hostname.includes(":");
  }

  function extractFeatures(rawUrl) {
    const raw = String(rawUrl).trim();
    const url = new URL(raw.includes("://") ? raw : `https://${raw}`);
    const hostname = url.hostname.toLowerCase();
    const labels = hostname.split(".").filter(Boolean);
    const tld = labels.at(-1) || "";
    const completeText = `${hostname}${url.pathname}${url.search}`.toLowerCase();
    const digitCount = [...raw].filter((character) => /\d/.test(character)).length;
    const specialCount = [...raw].filter((character) => !/[A-Za-z0-9]/.test(character)).length;
    const query = url.search.length ? url.search.slice(1) : "";

    return [
      raw.length, hostname.length, url.pathname.length, query.length, Math.max(0, labels.length - 2),
      digitCount, digitCount / Math.max(1, raw.length), specialCount, (hostname.match(/-/g) || []).length,
      (hostname.match(/\./g) || []).length, (raw.match(/\//g) || []).length, Number(url.protocol === "https:"),
      Number(isIpAddress(hostname)), Number(hostname.includes("xn--")), Number(raw.includes("@")),
      Number(/%[0-9a-f]{2}/i.test(raw)), entropy(hostname.replace(/\./g, "")),
      KEYWORDS.filter((word) => completeText.includes(word)).length, Number(RISKY_TLDS.has(tld)),
      query ? query.split("&").length : 0
    ];
  }

  function sigmoid(value) {
    if (value >= 0) return 1 / (1 + Math.exp(-value));
    const exponent = Math.exp(value);
    return exponent / (1 + exponent);
  }

  async function loadModel() {
    if (root.PhishGuardModel) return root.PhishGuardModel;
    const response = await fetch(chrome.runtime.getURL("ml/model.json"));
    if (!response.ok) throw new Error("Model file could not be loaded.");
    root.PhishGuardModel = await response.json();
    return root.PhishGuardModel;
  }

  async function predict(rawUrl) {
    try {
      const model = await loadModel();
      const values = extractFeatures(rawUrl);
      let logit = model.intercept;
      values.forEach((value, index) => {
        logit += ((value - model.means[index]) / (model.scales[index] || 1)) * model.coefficients[index];
      });
      const probability = sigmoid(logit);
      return { available: true, probability, score: Math.round(probability * 100), label: probability >= model.threshold ? "Likely phishing" : "Likely legitimate", featureCount: values.length };
    } catch (error) {
      return { available: false, probability: null, score: null, label: "Model unavailable", error: error.message };
    }
  }

  root.PhishGuardML = { extractFeatures, loadModel, predict };
})(globalThis);
