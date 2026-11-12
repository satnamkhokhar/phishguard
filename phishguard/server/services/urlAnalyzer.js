
/*
    PhishGuard - URL Analysis Engine

    Analyzes the text of a URL using explainable rules.

    IMPORTANT:
    - Does not visit or download the website.
    - Does not execute remote code.
    - Results are heuristic warning indicators,
      not proof that a URL is safe or malicious.
*/

const net = require("node:net");

// Maximum URL length accepted by the application
const MAX_URL_LENGTH = 2048;

/*
    Main URL analysis function.

    Returns:
    {
        url,
        hostname,
        score,
        classification,
        indicators,
        summary
    }
*/
function analyzeURL(input) {

    // Validate the submitted value
    if (typeof input !== "string" || !input.trim()) {
        throw new Error("Please enter a URL.");
    }

    const urlText = input.trim();

    if (urlText.length > MAX_URL_LENGTH) {
        throw new Error("The URL must be 2048 characters or fewer.");
    }

    // Require an explicit HTTP or HTTPS protocol
    if (!/^https?:\/\//i.test(urlText)) {
        throw new Error("The URL must start with http:// or https://.");
    }

    let parsed;

    try {
        parsed = new URL(urlText);
    } catch {
        throw new Error("Please enter a valid website URL.");
    }

    // Reject URLs without a usable hostname
    if (!parsed.hostname) {
        throw new Error("The URL must contain a valid hostname.");
    }

    // Only analyze HTTP and HTTPS URLs
    if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("Only HTTP and HTTPS URLs are supported.");
    }

    // Reject URLs containing embedded credentials
    if (parsed.username || parsed.password) {
        throw new Error(
            "URLs containing embedded usernames or passwords are not supported."
        );
    }

    const hostname = parsed.hostname.toLowerCase();
    const indicators = [];
    let score = 0;

    /*
        Helper function for adding analysis indicators.

        Each indicator includes:
        - Name
        - Whether the condition was detected
        - Explanation
        - Score contribution
    */
    function addIndicator(name, detected, explanation, points = 0) {
        indicators.push({
            name,
            detected,
            explanation,
            points: detected ? points : 0
        });

        if (detected) {
            score += points;
        }
    }

    /*
        Rule 1: HTTPS

        HTTP does not provide the transport encryption
        normally provided by HTTPS.
    */
    const usesHTTP = parsed.protocol === "http:";

    addIndicator(
        "HTTP Connection",
        usesHTTP,
        usesHTTP
            ? "This URL uses HTTP instead of HTTPS."
            : "This URL uses HTTPS.",
        15
    );

    /*
        Rule 2: IP Address

        Some suspicious URLs use IP addresses rather
        than recognizable domain names.
    */
    const ipHost = net.isIP(hostname) !== 0 ||
        net.isIP(hostname.replace(/^\[|\]$/g, "")) !== 0;

    addIndicator(
        "IP Address Hostname",
        ipHost,
        ipHost
            ? "The URL uses an IP address as its hostname."
            : "The hostname is not an IP address.",
        20
    );

    /*
        Rule 3: Excessive URL Length

        Very long URLs can make important hostname
        or path information harder to inspect.
    */
    const longURL = urlText.length > 75;
    const veryLongURL = urlText.length > 150;

    addIndicator(
        "Long URL",
        longURL,
        longURL
            ? `The URL contains ${urlText.length} characters.`
            : "The URL length is within the selected threshold.",
        veryLongURL ? 20 : 10
    );

    /*
        Rule 4: Suspicious Keywords

        Check for account-verification, recovery,
        and urgency-related wording.

        These words can also appear on legitimate sites.
    */
    const suspiciousWords = [
        "verify",
        "verification",
        "password-reset",
        "reset-password",
        "account-update",
        "confirm-account",
        "urgent",
        "suspended",
        "security-alert"
    ];

    const matchingWords = suspiciousWords.filter((word) =>
        urlText.toLowerCase().includes(word)
    );

    const keywordPoints = Math.min(matchingWords.length * 10, 20);

    addIndicator(
        "Suspicious Keywords",
        matchingWords.length > 0,
        matchingWords.length > 0
            ? `Potentially suspicious wording: ${matchingWords.join(", ")}.`
            : "No selected suspicious keywords were detected.",
        keywordPoints
    );

    /*
        Rule 5: Excessive Subdomains

        Count hostname labels. This is a simple
        heuristic, not a public-suffix-aware calculation.
    */
    const hostnameParts = hostname
        .replace(/^\[|\]$/g, "")
        .split(".");

    const deepHostname = !ipHost && hostnameParts.length > 4;

    addIndicator(
        "Deep Hostname Structure",
        deepHostname,
        deepHostname
            ? "The hostname contains several nested labels."
            : "No unusually deep hostname structure was detected.",
        10
    );

    /*
        Rule 6: @ Symbol

        An @ symbol in a URL can be misleading.
        This application rejects credentials in the
        URL authority and flags other occurrences.
    */
    const containsAtSymbol = urlText.includes("@");

    addIndicator(
        "@ Symbol",
        containsAtSymbol,
        containsAtSymbol
            ? "The URL contains an @ symbol."
            : "No @ symbol was detected.",
        10
    );

    /*
        Rule 7: Excessive Percent Encoding

        Percent-encoded characters are valid URL syntax,
        but unusually frequent encoding can make URLs
        harder to understand.
    */
    const encodedMatches = urlText.match(/%[0-9a-f]{2}/gi) || [];
    const excessiveEncoding = encodedMatches.length >= 4;

    addIndicator(
        "Excessive URL Encoding",
        excessiveEncoding,
        excessiveEncoding
            ? "Multiple percent-encoded characters were detected."
            : "No excessive percent encoding was detected.",
        10
    );

    /*
        Rule 8: Punycode

        Punycode is commonly used for internationalized
        domain names and is not inherently malicious.
    */
    const hasPunycode = hostname
        .split(".")
        .some((label) => label.startsWith("xn--"));

    addIndicator(
        "Punycode Hostname",
        hasPunycode,
        hasPunycode
            ? "The hostname contains an internationalized domain label."
            : "No Punycode labels were detected.",
        10
    );

    // Keep scores within the documented 0-100 range
    score = Math.min(score, 100);

    /*
        Determine the risk category from the heuristic score.
    */
    let classification;

    if (score < 25) {
        classification = "Low Risk";
    } else if (score < 60) {
        classification = "Moderate Risk";
    } else {
        classification = "High Risk";
    }

    // Generate an explanation appropriate to the category
    const summaries = {
        "Low Risk":
            "Few selected warning indicators were detected.",
        "Moderate Risk":
            "Some URL characteristics deserve closer inspection.",
        "High Risk":
            "Several warning indicators were detected. Use extra caution."
    };

    // Return the complete structured analysis
    return {
        url: urlText,
        hostname,
        score,
        classification,
        indicators,
        summary: summaries[classification]
    };
}

// Export the analyzer for Express routes and automated tests
module.exports = {
    analyzeURL
};
