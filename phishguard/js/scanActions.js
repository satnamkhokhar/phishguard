
/*
    PhishGuard - Saved Scan Actions

    Ask the user to confirm before permanently
    deleting a saved scan.
*/

// Find every Delete Scan form on the current page
const deleteForms = document.querySelectorAll(
    ".delete-scan-form"
);

// Attach a confirmation handler to each form
deleteForms.forEach((form) => {

    form.addEventListener("submit", (event) => {

        const confirmed = window.confirm(
            "Are you sure you want to delete this scan? " +
            "This action cannot be undone."
        );

        // Cancel the request if the user chooses Cancel
        if (!confirmed) {
            event.preventDefault();
        }

    });

});
