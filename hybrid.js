/* ML is evaluated first. Heuristics add an explainable, independent score. */
(function (root) {
  "use strict";
  function riskLevel(score) {
    return score >= 75 ? "Critical" : score >= 50 ? "High risk" : score >= 20 ? "Suspicious" : "Low risk";
  }

  async function analyse(rawUrl) {
    const ml = await root.PhishGuardML.predict(rawUrl);
    const heuristic = root.PhishGuardRules.scoreUrl(rawUrl);
    if (!heuristic.valid) return { ...heuristic, ml, heuristic };
    const score = ml.available ? Math.round((ml.score * 0.60) + (heuristic.score * 0.40)) : heuristic.score;
    return { ...heuristic, score, level: riskLevel(score), ml, heuristic };
  }

  root.PhishGuardHybrid = { analyse };
})(globalThis);
