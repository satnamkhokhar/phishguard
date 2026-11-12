
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
                        <a href="/analyze"
                           class="analyze-again">
                            Analyze Another URL
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
