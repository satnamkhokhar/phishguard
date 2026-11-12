
/*
    PhishGuard - Analyzer Form Validation

    Provides immediate input validation in the browser.

    Server-side validation remains mandatory because
    browser-side JavaScript can be bypassed.
*/

const analyzeForm = document.getElementById("analyze-form");
const urlInput = document.getElementById("url-input");
const errorMessage = document.getElementById("url-error");

// Only run if the analyzer form exists on the current page
if (analyzeForm && urlInput && errorMessage) {

    analyzeForm.addEventListener("submit", (event) => {

        // Remove any previous validation error
        errorMessage.textContent = "";

        const input = urlInput.value.trim();

        // Check for an empty URL
        if (!input) {
            event.preventDefault();
            errorMessage.textContent = "Please enter a URL.";
            return;
        }

        // Require an explicit HTTP or HTTPS protocol
        if (!/^https?:\/\//i.test(input)) {
            event.preventDefault();
            errorMessage.textContent =
                "The URL must start with http:// or https://.";
            return;
        }

        // Ensure the URL is not excessively long
        if (input.length > 2048) {
            event.preventDefault();
            errorMessage.textContent =
                "The URL must be 2048 characters or fewer.";
            return;
        }

        // Use the browser's URL parser to check syntax
        try {
            const parsed = new URL(input);

            if (!["http:", "https:"].includes(parsed.protocol)) {
                throw new Error("Unsupported protocol");
            }

            if (parsed.username || parsed.password) {
                throw new Error("Embedded credentials");
            }

        } catch {
            event.preventDefault();
            errorMessage.textContent =
                "Please enter a valid HTTP or HTTPS URL.";
        }
    });

    // Clear validation messages when the user edits the input
    urlInput.addEventListener("input", () => {
        errorMessage.textContent = "";
    });
}
