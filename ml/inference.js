/* PhishGuard AI - Model inference (9 hostname features) */
(function (root) {
  "use strict";

  const SUSPICIOUS_KEYWORDS = new Set([
    "login", "signin", "verify", "verification",
    "account", "secure", "security", "update",
    "password", "credential", "authenticate",
    "bank", "banking", "payment", "billing",
    "wallet", "card", "transaction", "urgent",
    "suspended", "blocked", "expired"
  ]);

  const TRACKING_PARAMETER_PATTERN =
    /^(utm_.+|gclid|gbraid|wbraid|gad_.+|dclid|fbclid|msclkid|mc_cid|mc_eid|_ga|yclid|igshid)$/i;

  const SECOND_LEVEL_LABELS = new Set([
    "co", "com", "ac", "edu", "gov", "org", "net", "or", "ne", "go"
  ]);

  const FEATURE_NAMES = [
    "host_length", "deep_subdomain_count", "digit_ratio", "hyphen_count",
    "has_userinfo", "has_https", "has_ip",
    "host_keyword_count", "has_punycode"
  ];

  function entropy(value) {
    if (!value) return 0;
    const counts = new Map();

    for (const character of value) {
      counts.set(character, (counts.get(character) || 0) + 1);
    }

    let result = 0;
    for (const count of counts.values()) {
      const p = count / value.length;
      result -= p * Math.log2(p);
    }
    return result;
  }

  function removeTrackingParameters(rawUrl) {
    try {
      const raw = String(rawUrl).trim();
      const input = raw.includes("://") ? raw : "https://" + raw;
      const url = new URL(input);

      for (const key of [...url.searchParams.keys()]) {
        if (TRACKING_PARAMETER_PATTERN.test(key)) {
          url.searchParams.delete(key);
        }
      }

      return url.href;
    } catch {
      return rawUrl;
    }
  }

  function extractFeatures(rawUrl) {
    const raw = String(rawUrl ?? "")
  .trim()
  .replace(/^["']|["']$/g, "");

if (!raw) {
  throw new Error("Please enter a URL to scan.");
}

let url;

try {
  url = new URL(
    raw.includes("://") ? raw : "https://" + raw
  );
} catch {
  throw new Error("Invalid URL. Enter a complete URL such as https://chatgpt.com/");
}

    let host = (url.hostname || "").toLowerCase()
      .replace(/^\[|\]$/g, "").replace(/\.$/, "");
    const hasIp = (host.includes(":") ||
      /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) ? 1 : 0;
    if (host.startsWith("www.")) host = host.slice(4);

    const labels = host ? host.split(".") : [];

    // One subdomain level is normal; only levels beyond the first count.
    let deepSubdomainCount = 0;
    if (!hasIp && labels.length >= 2) {
      const suffixLen = (
        labels.length >= 3 &&
        labels[labels.length - 1].length === 2 &&
        SECOND_LEVEL_LABELS.has(labels[labels.length - 2])
      ) ? 2 : 1;
      const subdomainCount = Math.max(0, labels.length - suffixLen - 1);
      deepSubdomainCount = Math.max(0, subdomainCount - 1);
    }

    const keywordCount = host.split(/[^a-z0-9]+/)
      .filter(t => SUSPICIOUS_KEYWORDS.has(t)).length;
    const digitCount = (host.match(/\d/g) || []).length;

    return [
      host.length,
      deepSubdomainCount,
      digitCount / Math.max(host.length, 1),
      (host.match(/-/g) || []).length,
      Number(Boolean(url.username || url.password)),
      Number(url.protocol === "https:"),
      hasIp,
      keywordCount,
      Number(host.includes("xn--"))
    ];
  }

  function sigmoid(value) {
    if (value >= 0) return 1 / (1 + Math.exp(-value));
    const exponent = Math.exp(value);
    return exponent / (1 + exponent);
  }

  async function loadModel() {
    if (root.PhishGuardModel) {
      const cached = root.PhishGuardModel;
      if (cached.feature_count !== FEATURE_NAMES.length) {
        throw new Error("Cached model has the wrong feature count. Reload the extension.");
      }
      return cached;
    }

    const response = await fetch(chrome.runtime.getURL("ml/model.json"));
    if (!response.ok) {
      throw new Error("Model file could not be loaded.");
    }

    const model = await response.json();

    if (
      model.feature_count !== FEATURE_NAMES.length ||
      !Array.isArray(model.feature_names) ||
      model.feature_names.length !== FEATURE_NAMES.length ||
      !FEATURE_NAMES.every((name, i) => model.feature_names[i] === name) ||
      !Array.isArray(model.scaler_mean) ||
      model.scaler_mean.length !== FEATURE_NAMES.length ||
      !Array.isArray(model.scaler_scale) ||
      model.scaler_scale.length !== FEATURE_NAMES.length ||
      !Array.isArray(model.coefficients) ||
      !Array.isArray(model.coefficients[0]) ||
      model.coefficients[0].length !== FEATURE_NAMES.length ||
      !Array.isArray(model.intercept) ||
      model.intercept.length < 1
    ) {
      throw new Error(
  "Model mismatch: " + JSON.stringify({
    feature_count: model.feature_count,
    feature_names: model.feature_names?.length,
    scaler_mean: model.scaler_mean?.length,
    scaler_scale: model.scaler_scale?.length,
    coefficients: model.coefficients?.[0]?.length,
    expected: FEATURE_NAMES.length
  })
);
    }

    root.PhishGuardModel = model;
    return model;
  }

  async function predict(rawUrl) {
    try {
      const model = await loadModel();
      const modelInput = removeTrackingParameters(String(rawUrl).trim());
      const values = extractFeatures(modelInput);

      let logit = model.intercept[0];
      const coefficients = model.coefficients[0];

      values.forEach((value, index) => {
        const scale = model.scaler_scale[index];
        if (!Number.isFinite(scale) || scale === 0) {
          throw new Error("Invalid scaler value at feature " + index);
        }

        logit +=
          ((value - model.scaler_mean[index]) / scale) *
          coefficients[index];
      });

      const probability = sigmoid(logit);

      console.log("URL used for ML:", modelInput);
      console.log("Feature names:", FEATURE_NAMES);
      console.log("Extracted features:", values);
      console.log("ML probability:", probability);

      return {
        available: true,
        probability,
        score: Math.round(probability * 100),
        label: probability >= 0.5
          ? "Likely phishing"
          : "Likely legitimate",
        featureCount: values.length
      };
    } catch (error) {
      console.error("PhishGuard ML error:", error);
      return {
        available: false,
        probability: null,
        score: null,
        label: "Model unavailable",
        error: error.message
      };
    }
  }

  root.PhishGuardML = {
  extractFeatures,
  removeTrackingParameters,
  loadModel,
  preloadModel: loadModel,
  predict
};
})(globalThis);