/* Normalizes URL, model, and DOM outputs and applies the decision policy. */
(function (root) {
  "use strict";

  const SAFE_THRESHOLD = 35;
  const SUSPICIOUS_THRESHOLD = 50;
  const PHISHING_THRESHOLD = 50;

  function clampScore(value) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? Math.max(0, Math.min(100, numeric)) : 0;
  }

  function decisionFor(score) {
    if (score >= PHISHING_THRESHOLD) return "PHISHING";
    if (score >= SAFE_THRESHOLD && score < SUSPICIOUS_THRESHOLD) return "SUSPICIOUS";
    return "SAFE";
  }

  function riskLevel(score) {
    return decisionFor(clampScore(score));
  }

  function fuse({ mlScore, mlAvailable, urlHeurScore, domScore, extremeConfidence, hardExtreme, softExtreme, findings = [] }) {
    const normalizedML = clampScore(mlScore);
    const normalizedHeuristics = clampScore(urlHeurScore);
    const normalizedDOM = clampScore(domScore);
    const appliedRules = [];
    let fused;

    if (mlAvailable) {
      fused = 0.30 * normalizedML + 0.30 * normalizedHeuristics + 0.40 * normalizedDOM;
      appliedRules.push("weighted_fusion_ml_30_url_30_dom_40");
    } else {
      fused = 0.50 * normalizedHeuristics + 0.50 * normalizedDOM;
      appliedRules.push("weighted_fusion_url_50_dom_50");
    }
    fused = clampScore(Math.round(fused));

    const hasHardExtreme = Boolean(hardExtreme);
    const hasSoftExtreme = Boolean(softExtreme || (extremeConfidence && !hasHardExtreme));
    if (hasHardExtreme || (hasSoftExtreme && normalizedHeuristics >= 40)) {
      fused = Math.max(fused, 80);
      appliedRules.push("extreme_confidence_url_block");
      return { fused, decision: "PHISHING", appliedRules };
    }

    const findingIds = new Set(findings.map((finding) => typeof finding === "string" ? finding : finding?.id));
    const strongDomFinding = ["hidden_password_field", "password_form_cross_origin", "password_form_http"]
      .some((id) => findingIds.has(id));
    if (normalizedDOM >= 70 || strongDomFinding) {
      fused = Math.max(fused, 60);
      appliedRules.push(normalizedDOM >= 70 ? "strong_dom_score_floor_60" : "strong_dom_finding_floor_60");
    }

    return { fused: clampScore(fused), decision: decisionFor(fused), appliedRules };
  }

  function analyseUrl(rawUrl) {
    const ml = root.PhishGuardML.predict(rawUrl);
    const heuristic = root.PhishGuardRules.scoreUrl(rawUrl);
    const mlAvailable = Boolean(ml.available);
    return {
      url: heuristic.valid ? heuristic.url : String(rawUrl),
      valid: heuristic.valid,
      hostname: heuristic.hostname || "",
      mlScore: mlAvailable ? clampScore(ml.probability * 100) : null,
      mlAvailable,
      urlHeurScore: clampScore(heuristic.score),
      hardExtreme: Boolean(heuristic.hardExtreme),
      softExtreme: Boolean(heuristic.softExtreme),
      extremeConfidence: Boolean(heuristic.extremeConfidence),
      urlFindings: heuristic.findings || [],
      featureSummary: heuristic.featureSummary || null,
      error: heuristic.error || null
    };
  }

  function combineWithDom(urlResult, domResult, previousDecision) {
    const domScore = clampScore(domResult?.domScore ?? domResult?.score);
    const fusedResult = fuse({
      mlScore: urlResult.mlScore,
      mlAvailable: urlResult.mlAvailable,
      urlHeurScore: urlResult.urlHeurScore,
      domScore,
      hardExtreme: urlResult.hardExtreme,
      softExtreme: urlResult.softExtreme,
      extremeConfidence: urlResult.extremeConfidence,
      findings: domResult?.findings || []
    });
    const rank = { SAFE: 0, SUSPICIOUS: 1, PHISHING: 2 };
    if (rank[previousDecision] > rank[fusedResult.decision]) {
      fusedResult.decision = previousDecision;
      fusedResult.appliedRules.push("navigation_decision_no_downgrade");
    }
    return {
      ...fusedResult,
      domScore,
      findings: [...(urlResult.urlFindings || []), ...(domResult?.findings || [])]
    };
  }

  function fuseUrlStage({ mlScore, mlAvailable, urlHeurScore }) {
    const normalizedML = clampScore(mlScore);
    const normalizedHeuristics = clampScore(urlHeurScore);
    const fused = clampScore(Math.round(mlAvailable
      ? 0.30 * normalizedML + 0.30 * normalizedHeuristics
      : normalizedHeuristics));
    return {
      fused,
      decision: decisionFor(fused),
      appliedRules: [mlAvailable ? "url_stage_preview_ml_30_url_30_dom_0" : "url_stage_preview_url_100"]
    };
  }

  // Compatibility wrapper for callers that still need a URL-only analysis result.
  async function analyse(rawUrl) {
    const result = analyseUrl(rawUrl);
    const fused = fuse({ ...result, domScore: 0 });
    return { ...result, ...fused, score: fused.fused, level: fused.decision, ml: { available: result.mlAvailable, score: result.mlScore }, heuristic: { score: result.urlHeurScore, findings: result.urlFindings } };
  }

  root.PhishGuardHybrid = {
    SAFE_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    PHISHING_THRESHOLD,
    clampScore,
    decisionFor,
    riskLevel,
    fuse,
    fuseUrlStage,
    analyseUrl,
    combineWithDom,
    analyse
  };
})(globalThis);
