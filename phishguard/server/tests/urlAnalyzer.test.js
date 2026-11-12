
/*
    PhishGuard URL Analyzer Tests

    Test core analysis behavior using Node's
    built-in test runner.
*/

const test = require("node:test");
const assert = require("node:assert/strict");

const { analyzeURL } = require("../services/urlAnalyzer");

// Verify HTTPS URLs receive a valid result
test("Analyzes a basic HTTPS URL", () => {
    const result = analyzeURL("https://example.com");

    assert.equal(result.hostname, "example.com");
    assert.equal(result.score, 0);
    assert.equal(result.classification, "Low Risk");
});

// Verify HTTP is flagged
test("Flags an HTTP URL", () => {
    const result = analyzeURL("http://example.com");

    assert.ok(result.score >= 15);
    assert.ok(
        result.indicators.some(
            (item) =>
                item.name === "HTTP Connection" &&
                item.detected
        )
    );
});

// Verify IP-based URLs are flagged
test("Flags an IP-address hostname", () => {
    const result = analyzeURL("http://192.0.2.10");

    assert.ok(
        result.indicators.some(
            (item) =>
                item.name === "IP Address Hostname" &&
                item.detected
        )
    );
});

// Verify suspicious keywords are detected
test("Detects selected suspicious wording", () => {
    const result = analyzeURL(
        "https://example.com/verify-account"
    );

    assert.ok(
        result.indicators.some(
            (item) =>
                item.name === "Suspicious Keywords" &&
                item.detected
        )
    );
});

// Verify empty input is rejected
test("Rejects an empty URL", () => {
    assert.throws(
        () => analyzeURL(""),
        /Please enter a URL/
    );
});

// Verify unsupported protocols are rejected
test("Rejects non-HTTP protocols", () => {
    assert.throws(
        () => analyzeURL("ftp://example.com"),
        /http:\/\/ or https:\/\//
    );
});

// Verify embedded credentials are rejected
test("Rejects URLs with embedded credentials", () => {
    assert.throws(
        () => analyzeURL("https://user:pass@example.com"),
        /embedded usernames or passwords/
    );
});

// Verify results stay within the documented score range
test("Keeps the risk score between 0 and 100", () => {
    const result = analyzeURL(
        "http://192.0.2.10/verify-account/urgent"
    );

    assert.ok(result.score >= 0);
    assert.ok(result.score <= 100);
});

// Verify analysis doesn't modify the submitted URL
test("Preserves the submitted URL", () => {
    const input = "https://example.com/test";

    const result = analyzeURL(input);

    assert.equal(result.url, input);
});
