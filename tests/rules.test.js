const assert = require("node:assert/strict");
const { scoreUrl, levenshtein } = require("../rules.js");

const safe = scoreUrl("https://www.example.com/products?id=14");
assert.equal(safe.valid, true);
assert.equal(safe.level, "Low risk");
assert.equal(safe.score, 0);

const ipHost = scoreUrl("http://192.168.1.55/verify-account");
assert.ok(ipHost.score >= 20);
assert.ok(ipHost.findings.some((item) => item.id === "ip-host"));

const typosquat = scoreUrl("https://paypa1-login-secure.xyz/verify");
assert.ok(typosquat.score >= 50);
assert.ok(typosquat.findings.some((item) => item.id === "typosquat"));

assert.equal(levenshtein("paypal", "paypa1"), 1);
assert.equal(scoreUrl("not a URL").valid, false);
console.log("All heuristic rule tests passed.");
