
/*
    PhishGuard - Node.js Backend

    This server handles:
    1. Serving the PhishGuard website
    2. User registration with MySQL
    3. Password hashing and login verification
    4. Login sessions and protected pages
    5. User logout
*/

// Load environment variables from the .env file
require("dotenv").config();

// Import required modules
const express = require("express");
const mysql = require("mysql2/promise");
const crypto = require("crypto");
const path = require("path");
const session = require("express-session");
const { analyzeURL } = require("./services/urlAnalyzer");

// Create the Express application
const app = express();
const PORT = 3000;

// Allow Express to read submitted HTML form data
app.use(express.urlencoded({ extended: false }));

/*
    SESSION CONFIGURATION

    Sessions remember whether a user has logged in.
    The session secret is stored privately in .env.
*/

// Ensure the session secret is configured
if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET is missing from server/.env");
}

// Configure login sessions
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false
    }
}));

/*
    AUTHENTICATION MIDDLEWARE

    Protect pages from visitors who have not logged in.
*/

// Check whether the user has an active login session
function requireLogin(req, res, next) {
    if (req.session.userId) {
        return next();
    }

    // Redirect unauthenticated visitors to Login
    return res.redirect("/login.html");
}

/*
    WEBSITE ROUTES

    Serve the existing PhishGuard pages and frontend files.
    Do not expose private server files or database credentials.
*/

// Serve the existing CSS and JavaScript folders
app.use("/css", express.static(path.join(__dirname, "..", "css")));
app.use("/js", express.static(path.join(__dirname, "..", "js")));

// Open Login first, or Home if the user is already logged in
app.get("/", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/index.html");
    }

    return res.redirect("/login.html");
});

// Protect the PhishGuard homepage
app.get("/index.html", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "..", "index.html"));
});

// Academy: protected educational page and interactive quiz.
app.get("/academy", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "..", "academy.html"));
});

// Protect the About page
app.get("/about.html", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "..", "about.html"));
});

/*
    URL ANALYZER PAGE

    Only authenticated users can access the
    URL analysis form.
*/
app.get("/analyze", requireLogin, (req, res) => {

    // Serve the existing analyzer HTML page
    return res.sendFile(
        path.join(__dirname, "views", "analyze.html")
    );
});

/*
    URL ANALYSIS ENDPOINT

    Receives a submitted URL, analyzes it using
    the rule-based engine, and displays the results.

    This route requires an authenticated session.
    No scan data is saved to MySQL in Part 2.
*/
app.post("/analyze", requireLogin, (req, res) => {

    try {

        // Analyze the URL submitted by the user
        const result = analyzeURL(req.body.url);

        // Escape user-controlled values before inserting them into HTML
        const safeURL = escapeHtml(result.url);
        const safeHostname = escapeHtml(result.hostname);

        // Escape analysis values before displaying them
        const safeClassification = escapeHtml(result.classification);
        const safeSummary = escapeHtml(result.summary);

        // Choose a CSS class based on the calculated score
        let riskClass = "risk-low";

        if (result.classification === "Moderate Risk") {
            riskClass = "risk-moderate";
        } else if (result.classification === "High Risk") {
            riskClass = "risk-high";
        }

        /*
            Generate HTML for each risk indicator.

            All displayed strings are escaped to prevent
            user input from becoming executable HTML.
        */
        const indicatorsHTML = result.indicators.map((item) => {

            const name = escapeHtml(item.name);
            const explanation = escapeHtml(item.explanation);

            const statusClass = item.detected
                ? "indicator-warning"
                : "indicator-clear";

            const statusText = item.detected
                ? "Flagged"
                : "Not flagged";

            return `
                <div class="indicator-item ${statusClass}">
                    <div class="indicator-heading">
                        <strong>${name}</strong>
                        <span>${statusText}</span>
                    </div>

                    <p>${explanation}</p>
                </div>
            `;

        }).join("");

        /*
            Send the results page.

            This uses the same CSS stylesheet and
            dark/light theme as the rest of PhishGuard.
        */
        return res.send(`
            <!DOCTYPE html>
            <html lang="en">

            <head>
                <meta charset="UTF-8">
                <meta name="viewport"
                      content="width=device-width, initial-scale=1.0">

                <title>Analysis Results | PhishGuard</title>

                <link rel="stylesheet"
                      href="/css/style.css">
            </head>

            <body>

                <header>
                    <h1>PhishGuard</h1>

                    <nav>
                        <a href="/index.html">Home</a>
                        <a href="/about.html">About</a>
                        <a href="/analyze">Analyze</a>
                        <a href="/academy">Academy</a>
                        <a href="/dashboard">Dashboard</a>
                        <a href="/history">History</a>
                        <a href="/profile">Profile</a>
                        <a href="/logout">Logout</a>

                        <button id="theme-toggle">
                            Light Mode
                        </button>
                    </nav>
                </header>

                <main class="analysis-page">

                    <section class="analysis-header">
                        <h2>URL Analysis Results</h2>
                        <p>
                            Review the URL characteristics
                            detected by PhishGuard.
                        </p>
                    </section>

                    <!-- Overall risk assessment -->
                    <section class="result-card ${riskClass}">

                        <h2>${safeClassification}</h2>

                        <p class="result-score">
                            ${result.score}/100
                        </p>

                        <p>${safeSummary}</p>

                        <p class="result-url">
                            <strong>Analyzed URL:</strong>
                            <span>${safeURL}</span>
                        </p>

                        <p>
                            <strong>Hostname:</strong>
                            ${safeHostname}
                        </p>
                    </section>

                    <!-- Explainable indicator details -->
                    <section class="result-details">

                        <h2>Analysis Details</h2>

                        ${indicatorsHTML}

                    </section>

                    <!-- Interpretation notice -->
                    <section class="analyzer-notice">

                        <h2>Important Note</h2>

                        <p>
                            This result is based on URL
                            characteristics only. A low
                            score does not guarantee safety,
                            and a high score does not prove
                            the website is malicious.
                        </p>

                        <p>
                            PhishGuard does not visit the
                            website or inspect its content.
                        </p>

                    </section>

                    <div class="analysis-actions">

                        <!-- Save the URL through a protected POST route -->
                        <form action="/scans" method="POST"
                            class="save-scan-form">

                            <input
                                type="hidden"
                                name="url"
                                value="${safeURL}"
                            >

                            <button type="submit" class="analyze-button">
                                Save Scan
                            </button>
                        </form>

                        <a href="/analyze" class="analyze-again">
                            Analyze Another URL
                        </a>

                        <a href="/history" class="analyze-again">
                            View Scan History
                        </a>

                    </div>

                </main>

                <footer>
                    <p>&copy; 2026 PhishGuard</p>
                </footer>

                <script src="/js/theme.js"></script>

            </body>
            </html>
        `);

    } catch (error) {

        /*
            Handle invalid input without exposing
            unexpected internal server errors.
        */
        if (error instanceof Error &&
            [
                "Please enter a URL.",
                "The URL must be 2048 characters or fewer.",
                "The URL must start with http:// or https://.",
                "Please enter a valid website URL.",
                "The URL must contain a valid hostname.",
                "Only HTTP and HTTPS URLs are supported.",
                "URLs containing embedded usernames or passwords are not supported."
            ].includes(error.message)) {

            return res.status(400).send(`
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport"
                          content="width=device-width, initial-scale=1.0">
                    <title>Invalid URL | PhishGuard</title>
                    <link rel="stylesheet"
                          href="/css/style.css">
                </head>
                <body>
                    <header>
                        <h1>PhishGuard</h1>
                    </header>

                    <main>
                        <section class="auth-container">
                            <h2>Unable to Analyze URL</h2>
                            <p>${escapeHtml(error.message)}</p>
                            <p>
                                <a href="/analyze">
                                    Back to Analyzer
                                </a>
                            </p>
                        </section>
                    </main>

                    <script src="/js/theme.js"></script>
                </body>
                </html>
            `);
        }

        // Log unexpected errors for debugging
        console.error("URL analysis error:", error);

        return res.status(500).send(
            "Unable to analyze the URL at this time."
        );
    }
});

/*
    CREATE SCAN

    Save a URL analysis to MySQL.

    Security:
    - Login is required.
    - User ID comes from the server session.
    - The URL is analyzed again on the server.
    - SQL parameters prevent SQL injection.
*/
app.post("/scans", requireLogin, async (req, res) => {

    let result;

    // Validate and analyze the submitted URL
    try {
        result = analyzeURL(req.body.url);
    } catch (error) {
        return res.status(400).send(
            "Invalid URL. Please return to the analyzer."
        );
    }

    try {

        // Save the complete analysis for the logged-in user
        const sql = `
            INSERT INTO scans
                (user_id, url, hostname, risk_score,
                 classification, summary, indicators)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;

        const values = [
            req.session.userId,
            result.url,
            result.hostname,
            result.score,
            result.classification,
            result.summary,
            JSON.stringify(result.indicators)
        ];

        const [insertResult] = await pool.execute(sql, values);

        // Redirect to the newly saved scan's detail page
        return res.redirect(`/scans/${insertResult.insertId}`);

    } catch (error) {

        console.error("Save scan error:", error);

        return res.status(500).send(
            "Unable to save scan. Please try again."
        );
    }
});

/*
    READ SCAN HISTORY

    Retrieve only the scans belonging to
    the authenticated user.
*/
app.get("/history", requireLogin, async (req, res) => {

    try {

        // Never retrieve scans without filtering by user_id
        const sql = `
            SELECT id, url, hostname, risk_score,
                   classification, created_at
            FROM scans
            WHERE user_id = ?
            ORDER BY created_at DESC, id DESC
        `;

        const [scans] = await pool.execute(
            sql,
            [req.session.userId]
        );

        // Generate a row for each saved scan
        const rowsHTML = scans.map((scan) => {

            const safeURL = escapeHtml(scan.url);
            const safeClassification = escapeHtml(
                scan.classification
            );

            const savedDate = new Date(
                scan.created_at
            ).toLocaleString();

            return `
                <tr>
                    <td class="history-url">${safeURL}</td>
                    <td>${scan.risk_score}/100</td>
                    <td>${safeClassification}</td>
                    <td>${escapeHtml(savedDate)}</td>
                    <td>
                        <div class="history-actions">

                            <a href="/scans/${scan.id}">
                                View Details
                            </a>

                            <a href="/scans/${scan.id}/edit">
                                Edit
                            </a>

                            <form
                                action="/scans/${scan.id}/delete"
                                method="POST"
                                class="delete-scan-form"
                            >
                                <button
                                    type="submit"
                                    class="history-delete-button"
                                >
                                    Delete
                                </button>
                            </form>

                        </div>
                    </td>
                </tr>
            `;
        }).join("");

        // Display a helpful message when no scans exist
        const historyContent = scans.length === 0
            ? `
                <div class="empty-history">
                    <h2>No Saved Scans Yet</h2>
                    <p>
                        Analyze a URL and click Save Scan
                        to start building your history.
                    </p>
                    <a href="/analyze"
                       class="analyze-again">
                        Analyze a URL
                    </a>
                </div>
              `
            : `
                <div class="history-table-wrapper">
                    <table class="history-table">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Score</th>
                                <th>Classification</th>
                                <th>Saved At</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rowsHTML}
                        </tbody>
                    </table>
                </div>
              `;

        return res.send(`
            <!DOCTYPE html>
            <html lang="en">

            <head>
                <meta charset="UTF-8">
                <meta name="viewport"
                      content="width=device-width, initial-scale=1.0">
                <title>Scan History | PhishGuard</title>
                <link rel="stylesheet"
                      href="/css/style.css">
            </head>

            <body>
                <header>
                    <h1>PhishGuard</h1>

                    <nav>
                        <a href="/index.html">Home</a>
                        <a href="/about.html">About</a>
                        <a href="/analyze">Analyze</a>
                        <a href="/academy">Academy</a>
                        <a href="/dashboard">Dashboard</a>
                        <a href="/history">History</a>
                        <a href="/profile">Profile</a>
                        <a href="/logout">Logout</a>
                        <button id="theme-toggle">
                            Light Mode
                        </button>
                    </nav>
                </header>

                <main>
                    <section class="analysis-header">
                        <h2>My Scan History</h2>
                        <p>
                            View the URL analyses you
                            have saved to PhishGuard.
                        </p>
                    </section>

                    ${historyContent}
                </main>

                <footer>
                    <p>&copy; 2026 PhishGuard</p>
                </footer>

                <script src="/js/theme.js"></script>
                <script src="/js/scanActions.js"></script>
            </body>
            </html>
        `);

    } catch (error) {

        console.error("Scan history error:", error);

        return res.status(500).send(
            "Unable to load scan history."
        );
    }
});

/*
    READ INDIVIDUAL SCAN

    Display a previously saved analysis.

    Security:
    The SQL query checks both the scan ID
    and the currently authenticated user ID.
*/
app.get("/scans/:id", requireLogin, async (req, res) => {

    // Only accept positive integer scan IDs
    const scanId = req.params.id;

    if (!/^[1-9]\d*$/.test(scanId)) {
        return res.status(404).send("Scan not found.");
    }

    try {

        // Only retrieve scans owned by the current user
        const sql = `
            SELECT id, url, hostname, risk_score,
                   classification, summary, indicators,
                   created_at
            FROM scans
            WHERE id = ? AND user_id = ?
        `;

        const [rows] = await pool.execute(
            sql,
            [scanId, req.session.userId]
        );

        // Return the same response for missing or unowned scans
        if (rows.length === 0) {
            return res.status(404).send("Scan not found.");
        }

        const scan = rows[0];
        const scanNumber = await getUserScanNumber(
            req.session.userId,
            scan.id
        );

        // mysql2 normally parses MySQL JSON columns automatically
        const indicators = typeof scan.indicators === "string"
            ? JSON.parse(scan.indicators)
            : scan.indicators;

        // Choose the appropriate risk styling
        const riskClass = scan.classification === "High Risk"
            ? "risk-high"
            : scan.classification === "Moderate Risk"
                ? "risk-moderate"
                : "risk-low";

        // Display the stored analysis indicators
        const indicatorsHTML = indicators.map((item) => `
            <div class="indicator-item ${
                item.detected
                    ? "indicator-warning"
                    : "indicator-clear"
            }">
                <div class="indicator-heading">
                    <strong>${escapeHtml(item.name)}</strong>
                    <span>
                        ${item.detected ? "Flagged" : "Not flagged"}
                    </span>
                </div>

                <p>${escapeHtml(item.explanation)}</p>
            </div>
        `).join("");

        return res.send(`
            <!DOCTYPE html>
            <html lang="en">

            <head>
                <meta charset="UTF-8">
                <meta name="viewport"
                      content="width=device-width, initial-scale=1.0">
                <title>Saved Scan | PhishGuard</title>
                <link rel="stylesheet"
                      href="/css/style.css">
            </head>

            <body>
                <header>
                    <h1>PhishGuard</h1>

                    <nav>
                        <a href="/index.html">Home</a>
                        <a href="/about.html">About</a>
                        <a href="/analyze">Analyze</a>
                        <a href="/academy">Academy</a>
                        <a href="/dashboard">Dashboard</a>
                        <a href="/history">History</a>
                        <a href="/profile">Profile</a>
                        <a href="/logout">Logout</a>
                        <button id="theme-toggle">
                            Light Mode
                        </button>
                    </nav>
                </header>

                <main class="analysis-page">

                    <section class="analysis-header">
                        <h2>Saved Scan #${scanNumber}</h2>
                        <p>
                            Analysis saved on
                            ${escapeHtml(
                                new Date(
                                    scan.created_at
                                ).toLocaleString()
                            )}
                        </p>
                    </section>

                    <section class="result-card ${riskClass}">
                        <h2>${escapeHtml(scan.classification)}</h2>

                        <p class="result-score">
                            ${scan.risk_score}/100
                        </p>

                        <p>${escapeHtml(scan.summary)}</p>

                        <p class="result-url">
                            <strong>URL:</strong>
                            <span>${escapeHtml(scan.url)}</span>
                        </p>

                        <p>
                            <strong>Hostname:</strong>
                            ${escapeHtml(scan.hostname)}
                        </p>
                    </section>

                    <section class="result-details">
                        <h2>Saved Analysis Details</h2>
                        ${indicatorsHTML}
                    </section>

                    <section class="analyzer-notice">
                        <h2>About This Result</h2>
                        <p>
                            This is the analysis stored when
                            the scan was saved. It is a
                            heuristic assessment, not a
                            guarantee of website safety.
                        </p>
                    </section>
                    
                    <!-- Actions for this saved scan -->
                    <div class="analysis-actions">

                        <!-- UPDATE -->
                        <a
                            href="/scans/${scan.id}/edit"
                            class="analyze-again"
                        >
                            Edit Scan
                        </a>

                        <!-- DELETE -->
                        <form
                            action="/scans/${scan.id}/delete"
                            method="POST"
                            class="delete-scan-form"
                        >
                            <button
                                type="submit"
                                class="delete-button"
                            >
                                Delete Scan
                            </button>
                        </form>

                        <!-- Navigation -->
                        <a href="/history" class="analyze-again">
                            Back to History
                        </a>

                        <a href="/analyze" class="analyze-again">
                            Analyze Another URL
                        </a>

                    </div>

                </main>

                <footer>
                    <p>&copy; 2026 PhishGuard</p>
                </footer>

                <script src="/js/theme.js"></script>
                <script src="/js/scanActions.js"></script>
            </body>
            </html>
        `);

    } catch (error) {

        console.error("Saved scan error:", error);

        return res.status(500).send(
            "Unable to load the saved scan."
        );
    }
});

/*
    PART 4: EDIT SCAN PAGE

    Show the edit form for a saved scan.
    Only the owner can access this page.
*/
app.get("/scans/:id/edit", requireLogin, async (req, res) => {

    const scanId = req.params.id;

    // Reject invalid scan IDs
    if (!/^[1-9]\d*$/.test(scanId)) {
        return res.status(404).send("Scan not found.");
    }

    try {

        // Retrieve only a scan owned by the logged-in user
        const sql = `
            SELECT id, url, risk_score, classification
            FROM scans
            WHERE id = ? AND user_id = ?
        `;

        const [rows] = await pool.execute(
            sql,
            [scanId, req.session.userId]
        );

        if (rows.length === 0) {
            return res.status(404).send("Scan not found.");
        }

        const scan = rows[0];
        const scanNumber = await getUserScanNumber(
            req.session.userId,
            scan.id
        );

        return res.send(`
            <!DOCTYPE html>
            <html lang="en">

            <head>
                <meta charset="UTF-8">
                <meta name="viewport"
                      content="width=device-width, initial-scale=1.0">

                <title>Edit Scan | PhishGuard</title>

                <link rel="stylesheet"
                      href="/css/style.css">
            </head>

            <body>

                <header>
                    <h1>PhishGuard</h1>

                    <nav>
                        <a href="/index.html">Home</a>
                        <a href="/about.html">About</a>
                        <a href="/analyze">Analyze</a>
                        <a href="/academy">Academy</a>
                        <a href="/dashboard">Dashboard</a>
                        <a href="/history">History</a>
                        <a href="/profile">Profile</a>
                        <a href="/logout">Logout</a>

                        <button id="theme-toggle">
                            Light Mode
                        </button>
                    </nav>
                </header>

                <main>

                    <section class="analysis-header">
                        <h2>Edit Saved Scan #${scanNumber}</h2>

                        <p>
                            Update the URL and PhishGuard
                            will calculate a new risk score.
                        </p>
                    </section>

                    <section class="analyzer-card">

                        <form
                            action="/scans/${scan.id}/update"
                            method="POST"
                            id="edit-scan-form"
                        >

                            <label for="url-input">
                                Website URL
                            </label>

                            <input
                                type="url"
                                id="url-input"
                                name="url"
                                value="${escapeHtml(scan.url)}"
                                maxlength="2048"
                                required
                            >

                            <p class="input-help">
                                Include http:// or https://.
                            </p>

                            <p class="input-help">
                                Previous score:
                                ${scan.risk_score}/100
                                (${escapeHtml(scan.classification)})
                            </p>

                            <p
                                id="url-error"
                                class="form-error"
                                role="alert"
                                aria-live="polite"
                            ></p>

                            <div class="edit-actions">

                                <button
                                    type="submit"
                                    class="analyze-button"
                                >
                                    Update & Re-analyze
                                </button>

                                <a
                                    href="/scans/${scan.id}"
                                    class="analyze-again"
                                >
                                    Cancel
                                </a>

                            </div>

                        </form>

                    </section>

                </main>

                <footer>
                    <p>&copy; 2026 PhishGuard</p>
                </footer>

                <script src="/js/theme.js"></script>

                <!-- Reuse existing Part 2 URL validation -->
                <script src="/js/analyze.js"></script>

            </body>
            </html>
        `);

    } catch (error) {

        console.error("Edit scan page error:", error);

        return res.status(500).send(
            "Unable to load the edit page."
        );
    }
});

/*
    PART 4: UPDATE SCAN

    Re-analyze a submitted URL and update the
    existing scan in MySQL.

    Security:
    - Login required
    - Server-side URL validation
    - Scan ownership enforced in SQL
    - Parameterized SQL queries
*/
app.post("/scans/:id/update", requireLogin, async (req, res) => {

    const scanId = req.params.id;

    // Reject invalid IDs
    if (!/^[1-9]\d*$/.test(scanId)) {
        return res.status(404).send("Scan not found.");
    }

    try {

        // Confirm this scan belongs to the current user
        const [existingScans] = await pool.execute(
            `SELECT id FROM scans
             WHERE id = ? AND user_id = ?`,
            [scanId, req.session.userId]
        );

        if (existingScans.length === 0) {
            return res.status(404).send("Scan not found.");
        }

        // Recalculate all results on the server
        let result;

        try {
            result = analyzeURL(req.body.url);
        } catch (validationError) {
            return res.status(400).send(
                "Invalid URL. Please return to the edit page."
            );
        }

        // Update the existing record, not create a new one
        const sql = `
            UPDATE scans
            SET
                url = ?,
                hostname = ?,
                risk_score = ?,
                classification = ?,
                summary = ?,
                indicators = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        `;

        const values = [
            result.url,
            result.hostname,
            result.score,
            result.classification,
            result.summary,
            JSON.stringify(result.indicators),
            scanId,
            req.session.userId
        ];

        const [updateResult] = await pool.execute(
            sql,
            values
        );

        // Handle a scan deleted by another request
        if (updateResult.affectedRows === 0) {
            return res.status(404).send("Scan not found.");
        }

        // Return to the same scan's details
        return res.redirect(`/scans/${scanId}`);

    } catch (error) {

        console.error("Update scan error:", error);

        return res.status(500).send(
            "Unable to update scan. Please try again."
        );
    }
});

/*
    PART 4: DELETE SCAN

    Permanently delete a saved scan.
    Only the logged-in owner can delete it.
*/
app.post("/scans/:id/delete", requireLogin, async (req, res) => {

    const scanId = req.params.id;

    // Validate the scan ID
    if (!/^[1-9]\d*$/.test(scanId)) {
        return res.status(404).send("Scan not found.");
    }

    try {

        // Delete only scans owned by the logged-in user
        const sql = `
            DELETE FROM scans
            WHERE id = ? AND user_id = ?
        `;

        const [deleteResult] = await pool.execute(
            sql,
            [scanId, req.session.userId]
        );

        // Return 404 if the scan does not exist or is not owned
        if (deleteResult.affectedRows === 0) {
            return res.status(404).send("Scan not found.");
        }

        // Return to History after successful deletion
        return res.redirect("/history");

    } catch (error) {

        console.error("Delete scan error:", error);

        return res.status(500).send(
            "Unable to delete scan. Please try again."
        );
    }
});


/*
    PART 5A: USER DASHBOARD

    Display personalized statistics and recent scans.
    All data belongs to the logged-in user.
*/
app.get("/dashboard", requireLogin, async (req, res) => {

    try {
        const userId = req.session.userId;
        const username = escapeHtml(req.session.username || "User");

        // Count the logged-in user's saved scans by risk level
        const statsSQL = `
            SELECT
                COUNT(*) AS total_scans,
                SUM(CASE WHEN classification = 'Low Risk'
                    THEN 1 ELSE 0 END) AS low_risk,
                SUM(CASE WHEN classification = 'Moderate Risk'
                    THEN 1 ELSE 0 END) AS moderate_risk,
                SUM(CASE WHEN classification = 'High Risk'
                    THEN 1 ELSE 0 END) AS high_risk
            FROM scans
            WHERE user_id = ?
        `;

        const [statsRows] = await pool.execute(statsSQL, [userId]);
        const stats = statsRows[0];

        // Retrieve the five most recent scans
        const recentSQL = `
            SELECT id, url, risk_score, classification, created_at
            FROM scans
            WHERE user_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT 5
        `;

        const [recentScans] = await pool.execute(recentSQL, [userId]);

        // Build the recent scans table
        const recentHTML = recentScans.length === 0
            ? `<p>No saved scans yet. Analyze a URL to get started!</p>`
            : `
                <div class="history-table-wrapper">
                    <table class="history-table">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Risk Level</th>
                                <th>Score</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${recentScans.map(scan => `
                                <tr>
                                    <td class="history-url">
                                        ${escapeHtml(scan.url)}
                                    </td>
                                    <td>
                                        ${escapeHtml(scan.classification)}
                                    </td>
                                    <td>${scan.risk_score}/100</td>
                                    <td>
                                        <a href="/scans/${scan.id}">
                                            View Details
                                        </a>
                                    </td>
                                </tr>
                            `).join("")}
                        </tbody>
                    </table>
                </div>
            `;

        return res.send(`
            <!DOCTYPE html>
            <html lang="en">

            <head>
                <meta charset="UTF-8">
                <meta name="viewport"
                      content="width=device-width, initial-scale=1.0">
                <title>Dashboard | PhishGuard</title>
                <link rel="stylesheet" href="/css/style.css">
            </head>

            <body>
                <header>
                    <h1>PhishGuard</h1>
                    <nav>
                        <a href="/index.html">Home</a>
                        <a href="/about.html">About</a>
                        <a href="/analyze">Analyze</a>
                        <a href="/academy">Academy</a>
                        <a href="/dashboard">Dashboard</a>
                        <a href="/history">History</a>
                        <a href="/profile">Profile</a>
                        <a href="/logout">Logout</a>
                        <button id="theme-toggle">Light Mode</button>
                    </nav>
                </header>

                <main class="dashboard-page">

                    <section class="analysis-header">
                        <h2>Welcome back, ${username}!</h2>
                        <p>
                            Here's an overview of your PhishGuard activity.
                        </p>
                    </section>

                    <section class="dashboard-stats">

                        <div class="stat-card">
                            <h3>Total Scans</h3>
                            <p>${stats.total_scans || 0}</p>
                        </div>

                        <div class="stat-card">
                            <h3>Low Risk</h3>
                            <p>${stats.low_risk || 0}</p>
                        </div>

                        <div class="stat-card">
                            <h3>Moderate Risk</h3>
                            <p>${stats.moderate_risk || 0}</p>
                        </div>

                        <div class="stat-card">
                            <h3>High Risk</h3>
                            <p>${stats.high_risk || 0}</p>
                        </div>

                    </section>

                    <section class="dashboard-recent">
                        <h2>Recent Scans</h2>
                        ${recentHTML}

                        <div class="analysis-actions">
                            <a href="/history" class="analyze-again">
                                View All History
                            </a>
                            <a href="/analyze" class="analyze-again">
                                Analyze New URL
                            </a>
                        </div>
                    </section>

                </main>

                <footer>
                    <p>&copy; 2026 PhishGuard</p>
                </footer>

                <script src="/js/theme.js"></script>
            </body>
            </html>
        `);

    } catch (error) {
        console.error("Dashboard error:", error);
        return res.status(500).send(
            "Unable to load dashboard. Please try again."
        );
    }
});

/*
    PART 5D: CURRENT USER

    Return the logged-in user's username.
    This endpoint is protected by the active session.
*/
app.get("/api/me", requireLogin, (req, res) => {
    return res.json({
        username: req.session.username || "User"
    });
});

/*
    PROFILE ENDPOINT

    Display the logged-in user's username using
    the information stored in their session.
*/

// Escape special HTML characters before displaying a username
function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (character) => {
        const entities = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;"
        };

        return entities[character];
    });
}

// Only authenticated users can access their profile
app.get("/profile", requireLogin, (req, res) => {

    // Retrieve the username from the active session
    const username = escapeHtml(req.session.username || "");

    // Display the username on a PhishGuard-styled page
    return res.send(`
        <!DOCTYPE html>
        <html lang="en">

        <head>
            <!-- Basic page settings -->
            <meta charset="UTF-8">
            <meta name="viewport"
                  content="width=device-width, initial-scale=1.0">

            <title>My Profile | PhishGuard</title>

            <!-- Reuse the existing website stylesheet -->
            <link rel="stylesheet" href="/css/style.css">
        </head>

        <body>

            <!-- Shared PhishGuard header -->
            <header>
                <h1>PhishGuard</h1>

                <!-- Navigation for authenticated users -->
                <nav>
                    <a href="/index.html">Home</a>
                    <a href="/about.html">About</a>
                    <a href="/analyze">Analyze</a>
                    <a href="/academy">Academy</a>
                    <a href="/dashboard">Dashboard</a>
                    <a href="/history">History</a>
                    <a href="/profile">Profile</a>
                    <a href="/logout">Logout</a>

                    <!-- Existing theme toggle -->
                    <button id="theme-toggle">Light Mode</button>
                </nav>
            </header>

            <!-- Profile information -->
            <main>
                <section class="auth-container">

                    <h2>My Profile</h2>

                    <!-- Username retrieved from the session -->
                    <p>Welcome, <strong>${username}</strong>!</p>

                    <p>
                        You are successfully logged in
                        to PhishGuard.
                    </p>

                </section>
            </main>

            <!-- Shared website footer -->
            <footer>
                <p>&copy; 2026 PhishGuard</p>
            </footer>

            <!-- Existing theme functionality -->
            <script src="/js/theme.js"></script>

        </body>
        </html>
    `);
});

// Serve the registration page
app.get("/register.html", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/index.html");
    }

    res.sendFile(path.join(__dirname, "public", "register.html"));
});

// Serve the login page
app.get("/login.html", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/index.html");
    }

    res.sendFile(path.join(__dirname, "public", "login.html"));
});

/*
    DATABASE CONNECTION

    Use the existing MySQL database credentials
    stored in the .env file.
*/

// Create a MySQL connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

/*
    Display-only scan number for the current user's existing scans.
    MySQL IDs remain global, unique primary keys for CRUD routes.
    Numbers can shift if older scans are deleted.
*/
async function getUserScanNumber(userId, scanId) {
    const [rows] = await pool.execute(
        `SELECT COUNT(*) AS scan_number
         FROM scans
         WHERE user_id = ? AND id <= ?`,
        [userId, scanId]
    );

    return Number(rows[0].scan_number);
}

/*
    PASSWORD SECURITY

    Generate salted password hashes using Node.js crypto.
    Plain-text passwords are never stored in MySQL.
*/

// Generate a password hash with the supplied salt
function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString("hex");
}

/*
    RESPONSE PAGE

    Display registration and login messages using
    the existing PhishGuard layout and theme.
*/

// Generate a styled response page
function responsePage(message, link, linkText) {
    return `
        <!DOCTYPE html>
        <html lang="en">

        <head>
            <!-- Basic page settings -->
            <meta charset="UTF-8">
            <meta name="viewport"
                  content="width=device-width, initial-scale=1.0">

            <title>PhishGuard</title>

            <!-- Use the existing PhishGuard stylesheet -->
            <link rel="stylesheet" href="/css/style.css">
        </head>

        <body>

            <!-- Shared PhishGuard header -->
            <header>
                <h1>PhishGuard</h1>

                <nav>
                    <a href="/login.html">Login</a>
                    <a href="/register.html">Register</a>

                    <!-- Existing dark/light theme toggle -->
                    <button id="theme-toggle">Light Mode</button>
                </nav>
            </header>

            <!-- Display the registration or login result -->
            <main>
                <section class="auth-container">
                    <h2>${message}</h2>

                    <!-- Link to the next page -->
                    <p>
                        <a href="${link}">${linkText}</a>
                    </p>
                </section>
            </main>

            <!-- Shared website footer -->
            <footer>
                <p>&copy; 2026 PhishGuard</p>
            </footer>

            <!-- Existing theme switcher -->
            <script src="/js/theme.js"></script>

        </body>
        </html>
    `;
}

/*
    REGISTRATION ENDPOINT

    Validate registration information, hash the password,
    and save the new user in the MySQL users table.
*/

app.post("/register", async (req, res) => {

    // Retrieve the submitted registration information
    const { username, email, password } = req.body;

    // Validate all required registration fields
    if (
        typeof username !== "string" ||
        typeof email !== "string" ||
        typeof password !== "string" ||
        !username.trim() ||
        !email.trim() ||
        username.length > 100 ||
        email.length > 150 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        password.length < 8
    ) {
        return res.status(400).send(
            responsePage(
                "Please enter valid registration information.",
                "/register.html",
                "Back to Registration"
            )
        );
    }

    try {
        // Generate a random salt for the password
        const salt = crypto.randomBytes(16).toString("hex");

        // Hash the submitted password
        const hashedPassword = hashPassword(password, salt);

        // Store the salt and hash together
        const storedPassword = `${salt}:${hashedPassword}`;

        // Insert the new user into the existing MySQL table
        const sql = `
            INSERT INTO users (name, username, email, password_hash)
            VALUES (?, ?, ?, ?)
        `;

        // Execute the parameterized SQL query
        await pool.execute(sql, [
            username.trim(),
            username.trim(),
            email.trim(),
            storedPassword
        ]);

        // Display the required registration success message
        return res.send(
            responsePage(
                "You have successfully registered",
                "/login.html",
                "Go to Login"
            )
        );

    } catch (error) {

        // Handle duplicate usernames or email addresses
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).send(
                responsePage(
                    "This username or email is already registered.",
                    "/register.html",
                    "Try Again"
                )
            );
        }

        // Log unexpected database errors
        console.error("Registration error:", error);

        return res.status(500).send(
            responsePage(
                "Registration failed. Please try again.",
                "/register.html",
                "Back to Registration"
            )
        );
    }
});

/*
    LOGIN ENDPOINT

    Verify the submitted username and password.
    Create a session only after successful authentication.
*/

app.post("/login", async (req, res) => {

    // Retrieve the submitted login credentials
    const { username, password } = req.body;

    // Display the required incorrect credentials message
    function loginFailed() {
        return res.status(401).send(
            responsePage(
                "The login credentials were incorrect",
                "/login.html",
                "Back to Login"
            )
        );
    }

    // Reject missing or invalid login information
    if (
        typeof username !== "string" ||
        typeof password !== "string" ||
        !username ||
        !password
    ) {
        return loginFailed();
    }

    try {
        // Retrieve the user ID, username, and password hash
        const sql = `
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
        `;

        const [rows] = await pool.execute(sql, [username]);

        // Reject unknown users or accounts without a password
        if (rows.length === 0 || !rows[0].password_hash) {
            return loginFailed();
        }

        // Separate the stored salt and password hash
        const parts = rows[0].password_hash.split(":");

        // Reject an invalid password hash format
        if (parts.length !== 2) {
            return loginFailed();
        }

        const [salt, storedHash] = parts;

        // Check the stored hash format
        if (
            !/^[a-f0-9]{32}$/i.test(salt) ||
            !/^[a-f0-9]{128}$/i.test(storedHash)
        ) {
            return loginFailed();
        }

        // Hash the entered password using the stored salt
        const calculatedHash = hashPassword(password, salt);

        // Convert hashes into buffers for secure comparison
        const storedBuffer = Buffer.from(storedHash, "hex");
        const calculatedBuffer = Buffer.from(calculatedHash, "hex");

        // Reject incorrect passwords
        if (
            storedBuffer.length !== calculatedBuffer.length ||
            !crypto.timingSafeEqual(storedBuffer, calculatedBuffer)
        ) {
            return loginFailed();
        }

        /*
            SUCCESSFUL LOGIN

            Create a fresh session and save the user ID.
            The user can now access Home and About.
        */

        req.session.regenerate((sessionError) => {

            // Handle session creation errors
            if (sessionError) {
                console.error("Session error:", sessionError);

                return res.status(500).send(
                    responsePage(
                        "Unable to start login session.",
                        "/login.html",
                        "Back to Login"
                    )
                );
            }

            // Store the authenticated user's ID and username in the session
            req.session.userId = rows[0].id;
            req.session.username = rows[0].username;

            // Save the session before sending the response
            req.session.save((saveError) => {

                // Handle session saving errors
                if (saveError) {
                    console.error("Session save error:", saveError);

                    return res.status(500).send(
                        responsePage(
                            "Unable to save login session.",
                            "/login.html",
                            "Back to Login"
                        )
                    );
                }

                // Display the required successful login message
                return res.send(
                    responsePage(
                        "You have logged in successfully",
                        "/index.html",
                        "Go to PhishGuard"
                    )
                );
            });
        });

    } catch (error) {

        // Log unexpected login errors
        console.error("Login error:", error);

        return res.status(500).send(
            responsePage(
                "Login failed. Please try again later.",
                "/login.html",
                "Back to Login"
            )
        );
    }
});

/*
    LOGOUT ENDPOINT

    Destroy the current login session and redirect
    the user back to the login page.
*/

app.post("/logout", (req, res) => {

    // Destroy the current session
    req.session.destroy((error) => {

        // Handle logout errors
        if (error) {
            console.error("Logout error:", error);

            return res.status(500).send(
                "Unable to log out."
            );
        }

        // Remove the session cookie from the browser
        res.clearCookie("connect.sid");

        // Return the user to Login
        return res.redirect("/login.html");
    });
});

/*
    LOGOUT LINK ENDPOINT

    Allows users to log out by clicking a link
    that points to /logout.
*/

app.get("/logout", (req, res) => {

    // Destroy the user's current session
    req.session.destroy((error) => {

        // Handle errors when destroying the session
        if (error) {
            console.error("Logout error:", error);

            return res.status(500).send(
                "Unable to log out."
            );
        }

        // Clear the session cookie from the browser
        res.clearCookie("connect.sid");

        // Redirect the user to the login page
        return res.redirect("/login.html");
    });
});


/*
    START SERVER

    Start PhishGuard on port 3000.
*/

app.listen(PORT, () => {
    console.log(`PhishGuard running at http://localhost:${PORT}`);
});
