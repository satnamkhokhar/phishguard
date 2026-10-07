/*
    PhishGuard Theme Switcher

    This JavaScript allows the user to switch between
    the default dark theme and the alternate light theme.

    The selected theme is saved using localStorage so
    the website remembers the user's choice after refreshing.
*/


// Finds the theme toggle button in the HTML.
const themeToggle = document.getElementById("theme-toggle");


// Checks if the user previously selected the light theme.
const savedTheme = localStorage.getItem("theme");


// If light mode was previously selected, apply it when the page loads.
if (savedTheme === "light") {
    document.body.classList.add("light-theme");
    themeToggle.textContent = "Dark Mode";
}


// Listens for the user to click the theme toggle button.
themeToggle.addEventListener("click", function () {

    // Adds or removes the light-theme class from the body.
    document.body.classList.toggle("light-theme");


    // Checks whether the light theme is currently active.
    if (document.body.classList.contains("light-theme")) {

        // Save the light theme preference.
        localStorage.setItem("theme", "light");

        // Change the button text.
        themeToggle.textContent = "Dark Mode";

    } else {

        // Save the dark theme preference.
        localStorage.setItem("theme", "dark");

        // Change the button text.
        themeToggle.textContent = "Light Mode";
    }

});