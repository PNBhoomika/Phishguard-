/* global module */
// PhishGuard's deterministic URL risk engine. It never sends a URL anywhere.
(function (root) {
  "use strict";

  const SUSPICIOUS_TLDS = new Set([
    "zip", "mov", "click", "top", "xyz", "tk", "gq", "ml", "cf", "work", "country", "rest", "loan", "racing"
  ]);
  const KEYWORDS = ["login", "signin", "verify", "verification", "secure", "update", "account", "wallet", "password", "confirm", "unlock", "payment"];
  const BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram", "netflix", "whatsapp", "linkedin", "bankofamerica"];

  function entropy(value) {
    if (!value) return 0;
    const frequency = {};
    for (const char of value) frequency[char] = (frequency[char] || 0) + 1;
    return Object.values(frequency).reduce((total, count) => {
      const probability = count / value.length;
      return total - probability * Math.log2(probability);
    }, 0);
  }

  function levenshtein(left, right) {
    const previous = Array.from({ length: right.length + 1 }, (_, index) => index);
    for (let i = 1; i <= left.length; i += 1) {
      const current = [i];
      for (let j = 1; j <= right.length; j += 1) {
        current[j] = Math.min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + (left[i - 1] === right[j - 1] ? 0 : 1));
      }
      previous.splice(0, previous.length, ...current);
    }
    return previous[right.length];
  }

  function isIpAddress(hostname) {
    const ipv4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(hostname);
    const ipv6 = hostname.includes(":");
    return ipv4 || ipv6;
  }

  function containsMixedScripts(hostname) {
    const hasLatin = /[A-Za-z]/.test(hostname);
    // Detects common non-Latin confusable-script ranges without penalising normal ASCII domains.
    const hasConfusableScript = /[\u0400-\u052F\u0370-\u03FF\u0530-\u058F]/.test(hostname);
    return hasLatin && hasConfusableScript;
  }

  function addFinding(findings, points, id, title, detail) {
    findings.push({ id, points, title, detail });
  }

  function scoreUrl(rawUrl) {
    const findings = [];
    let hardExtreme = false;
    let softExtreme = false;
    let url;
    try {
      url = new URL(rawUrl);
    } catch {
      return { valid: false, score: 0, level: "Invalid", findings: [], hardExtreme: false, softExtreme: false, extremeConfidence: false, error: "Enter a complete URL, for example https://example.com." };
    }

    if (!["http:", "https:"].includes(url.protocol)) {
      return { valid: false, score: 0, level: "Unsupported", findings: [], hardExtreme: false, softExtreme: false, extremeConfidence: false, error: "Only http and https URLs can be scanned." };
    }

    const hostname = url.hostname.toLowerCase().replace(/^www\./, "");
    const labels = hostname.split(".").filter(Boolean);
    const tld = labels.at(-1) || "";
    const pathAndQuery = `${url.pathname}${url.search}`.toLowerCase();
    const completeText = `${hostname}${pathAndQuery}`;

    if (isIpAddress(hostname)) {
      hardExtreme = true;
      addFinding(findings, 20, "ip-host", "IP address used as the host", "Legitimate public login pages rarely ask users to trust a raw IP address.");
    }
    if (hostname.includes("xn--")) {
      hardExtreme = true;
      addFinding(findings, 25, "punycode", "Punycode domain detected", "Punycode can be legitimate, but is often used to imitate brand names.");
    }
    if (containsMixedScripts(hostname)) addFinding(findings, 25, "mixed-script", "Mixed-script hostname", "Mixed writing systems can make look-alike domain names difficult to spot.");
    if (SUSPICIOUS_TLDS.has(tld)) addFinding(findings, 8, "risky-tld", `Higher-risk TLD: .${tld}`, "This TLD is not proof of phishing, but appears frequently in abuse reports.");
    if (labels.length >= 5) addFinding(findings, 10, "deep-subdomain", "Very deep subdomain chain", `${labels.length - 1} subdomain levels can hide the actual registrable domain.`);
    else if (labels.length === 4) addFinding(findings, 6, "deep-subdomain", "Deep subdomain chain", `${labels.length - 1} subdomain levels can obscure the destination.`);
    if (rawUrl.length > 150) addFinding(findings, 6, "long-url", "Unusually long URL", `${rawUrl.length} characters; long URLs can conceal suspicious parameters.`);
    if (rawUrl.includes("@")) addFinding(findings, 12, "at-symbol", "@ character in URL", "Everything before @ may be misleading; the browser navigates to the host after it.");
    if ((hostname.match(/-/g) || []).length >= 3) addFinding(findings, 5, "many-hyphens", "Many hyphens in hostname", "Hyphen-heavy domains are a common imitation pattern.");

    const matchedKeywords = KEYWORDS.filter((word) => completeText.includes(word));
    if (matchedKeywords.length >= 2) addFinding(findings, 10, "keywords", "Suspicious keyword cluster", `Found: ${matchedKeywords.slice(0, 4).join(", ")}.`);
    else if (matchedKeywords.length === 1) addFinding(findings, 4, "keyword", `Credential-related keyword: ${matchedKeywords[0]}`, "This is a weak signal on its own and is combined with other checks.");

    const hostEntropy = entropy(hostname.replace(/\./g, ""));
    if (hostEntropy >= 4.0 && hostname.length >= 18) addFinding(findings, 6, "entropy", "High-entropy hostname", "Random-looking hostnames can be generated for short-lived phishing campaigns.");

    const candidateLabels = labels.slice(0, -1)
      .filter((label) => !label.startsWith("xn--"))
      .flatMap((label) => label.split("-").filter((part) => part.length >= 4));
    for (const label of candidateLabels) {
      for (const brand of BRANDS) {
        const distance = levenshtein(label.replace(/\d/g, "a"), brand);
        if (label !== brand && distance > 0 && distance <= 1) {
          softExtreme = true;
          addFinding(findings, 30, "typosquat", `Possible ${brand} look-alike`, `The hostname segment “${label}” is ${distance} edit away from “${brand}”.`);
          break;
        }
      }
      if (findings.some((finding) => finding.id === "typosquat")) break;
    }

    const score = Math.max(0, Math.min(100, findings.reduce((total, finding) => total + finding.points, 0)));
    const level = score >= 75 ? "Critical" : score >= 50 ? "High risk" : score >= 20 ? "Suspicious" : "Low risk";
    return { valid: true, url: url.href, hostname, score, level, findings, hardExtreme, softExtreme, extremeConfidence: hardExtreme || softExtreme, featureSummary: { tld, labels: labels.length, entropy: Number(hostEntropy.toFixed(2)), keywordCount: matchedKeywords.length } };
  }

  root.PhishGuardRules = { scoreUrl, entropy, levenshtein };
  if (typeof module !== "undefined") module.exports = root.PhishGuardRules;
})(typeof globalThis !== "undefined" ? globalThis : window);
