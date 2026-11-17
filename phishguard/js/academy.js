/* PhishGuard Academy: client-side educational quiz. No database required. */
(() => {
    "use strict";
    const questions = [
        { question: "Which URL is the most suspicious?", options: ["https://accounts.google.com", "https://google-security-login.example.com", "https://www.google.com"], correct: 1, explanation: "The actual domain is example.com, not google.com. Familiar brand names in subdomains do not make a site official." },
        { question: "An email says your account will close in 10 minutes unless you click a link. What should you do?", options: ["Click immediately", "Reply with your password", "Visit the service using its official website or app"], correct: 2, explanation: "Artificial urgency is a common phishing tactic. Verify the claim through a trusted website or app." },
        { question: "Does HTTPS guarantee a website is legitimate?", options: ["Yes, HTTPS means the site is trustworthy", "No, phishing sites can also use HTTPS", "Only when using a laptop"], correct: 1, explanation: "HTTPS encrypts traffic, but scammers can obtain HTTPS certificates too. Always check the domain." },
        { question: "You receive an unexpected attachment from someone you know. What is the safest next step?", options: ["Open it because you recognize the sender", "Verify with the sender through a trusted channel", "Forward it to your contacts"], correct: 1, explanation: "Accounts can be compromised or impersonated. Confirm unexpected attachments before opening them." },
        { question: "What helps protect an account even if its password is stolen?", options: ["Reusing passwords", "Turning off login notifications", "Multi-factor authentication (MFA)"], correct: 2, explanation: "MFA adds another verification step. Phishing-resistant passkeys or security keys offer even stronger protection." }
    ];
    const root = document.getElementById("quiz-content");
    if (!root) return;
    let index = 0, score = 0, selected = null;
    function make(tag, className, value) {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (value !== undefined) node.textContent = value;
        return node;
    }
    function render() {
        root.replaceChildren();
        if (index === questions.length) {
            const result = make("div", "academy-result");
            result.append(make("p", "academy-kicker", "QUIZ COMPLETE"), make("p", "academy-result-score", `${score} / ${questions.length}`), make("h3", "", score === 5 ? "Phishing detective!" : score >= 3 ? "Nice work!" : "Keep practicing!"), make("p", "", "Every suspicious link you recognize is a step toward safer browsing."));
            const restart = make("button", "academy-button", "Try Again");
            restart.type = "button";
            restart.addEventListener("click", () => { index = 0; score = 0; selected = null; render(); });
            result.append(restart);
            root.append(result);
            return;
        }
        const q = questions[index];
        const top = make("div", "academy-quiz-top");
        top.append(make("span", "", `QUESTION ${index + 1} OF ${questions.length}`), make("span", "", `${index} / ${questions.length} ANSWERED`));
        const progress = make("div", "academy-progress");
        const bar = make("span");
        bar.style.width = `${index / questions.length * 100}%`;
        progress.append(bar);
        root.append(top, progress, make("h3", "", q.question));
        const options = make("div", "academy-options");
        q.options.forEach((answer, i) => {
            const button = make("button", "academy-option", answer);
            button.type = "button";
            if (selected !== null) {
                button.disabled = true;
                if (i === q.correct) button.classList.add("correct");
                else if (i === selected) button.classList.add("incorrect");
            }
            button.addEventListener("click", () => {
                if (selected !== null) return;
                selected = i;
                if (i === q.correct) score++;
                render();
            });
            options.append(button);
        });
        root.append(options);
        if (selected !== null) {
            const feedback = make("div", "academy-feedback");
            feedback.setAttribute("role", "status");
            feedback.append(make("strong", "", selected === q.correct ? "Correct!" : "Not quite — here's why:"), make("p", "", q.explanation));
            const actions = make("div", "academy-quiz-actions");
            const next = make("button", "academy-button", index === questions.length - 1 ? "See My Results" : "Next Question");
            next.type = "button";
            next.addEventListener("click", () => { index++; selected = null; render(); });
            actions.append(next);
            root.append(feedback, actions);
        }
    }
    render();
})();
