# PhishGuard

**A Full-Stack Phishing URL Analysis and Cybersecurity Awareness Application**

PhishGuard is a full-stack web application that helps users identify potentially suspicious URLs, understand common phishing indicators, and develop safer browsing habits.

Built as a final project for a Web Programming course, PhishGuard combines URL analysis, user authentication, database management, CRUD operations, and interactive cybersecurity education in one application.

The application uses an explainable, rule-based URL analyzer rather than a machine learning model. Each analysis provides a risk score, classification, and explanations of the indicators detected.

## Features

### 1. User Authentication and Session Management

- User registration with username, email, and password
- Password hashing using Node.js `crypto` with unique salts
- Login authentication using MySQL
- Session-based authentication using `express-session`
- Protected pages accessible only to authenticated users
- User profile displaying the logged-in username
- Logout functionality that destroys the active session

### 2. Phishing URL Analyzer

Users can submit HTTP or HTTPS URLs for analysis.

The analyzer evaluates several characteristics:

- HTTP connections without HTTPS
- IP-address-based hostnames
- Excessively long URLs
- Suspicious keywords
- Unusually deep subdomain structures
- `@` symbols
- Excessive percent encoding
- Punycode hostnames

Each URL receives a risk score between **0 and 100** and one of three classifications:

| Score | Classification |
|---|---|
| 0–24 | Low Risk |
| 25–59 | Moderate Risk |
| 60–100 | High Risk |

The analyzer also explains why individual indicators were or were not flagged.

**Important:** PhishGuard performs heuristic analysis of URL text. It does not visit websites, execute remote content, or guarantee that a URL is safe or malicious.

### 3. Saved Scan Management (CRUD)

Authenticated users can manage their saved URL analyses through four database operations.

| Operation | Functionality |
|---|---|
| Create | Save a URL analysis to MySQL |
| Read | View saved scan details and scan history |
| Update | Edit a saved URL and recalculate its risk score |
| Delete | Permanently remove a saved scan |

Every saved scan is associated with the authenticated user's account.

Database queries enforce ownership using the user's session ID, preventing users from accessing or modifying another account's saved scans through the application routes.

**Per-user scan numbering:** Saved scans are displayed with account-specific numbers, such as Scan #1 and Scan #2. The database maintains separate internal IDs for uniquely identifying records.

### 4. User Dashboard

The dashboard provides an overview of the authenticated user's activity, including:

- Total saved scans
- Low-risk scans
- Moderate-risk scans
- High-risk scans
- Five most recently saved scans
- Quick navigation to scan details and history

All dashboard statistics are calculated using the logged-in user's saved scans.

### 5. Scan History

Users can view their saved URL analyses in a table displaying:

- Analyzed URL
- Risk score
- Risk classification
- Date and time saved
- Options to view, edit, or delete the scan

Each account has its own scan history.

### 6. PhishGuard Academy

PhishGuard Academy is an educational section designed to help users recognize phishing attempts and improve their cybersecurity awareness.

It includes:

- Educational content about phishing and suspicious URLs
- Cybersecurity awareness resources
- References to trusted sources such as the FTC and CISA
- An interactive five-question phishing awareness quiz
- Immediate answer feedback and explanations
- Final quiz score and restart functionality

The Academy quiz runs entirely in the browser and does not require additional database tables.

Its HTML, CSS, and JavaScript are maintained separately for better organization.

### 7. User Interface

- Responsive layouts
- Dark and light themes
- Navigation between application sections
- Client-side URL form validation
- Server-side input validation
- Confirmation before deleting saved scans
- Consistent styling across pages

## Technology Stack

| Component | Technologies |
|---|---|
| Frontend | HTML5, CSS3, JavaScript |
| Backend | Node.js, Express.js |
| Database | MySQL |
| Authentication | express-session, Node.js crypto |
| Database Driver | mysql2 |
| Configuration | dotenv |
| Testing | Node.js built-in test runner |
| Version Control | Git and GitHub |

## Project Structure

```text
phishguard/
├── README.md
├── index.html
├── about.html
├── academy.html
├── css/
│   ├── style.css
│   └── academy.css
├── js/
│   ├── theme.js
│   ├── analyze.js
│   ├── scanActions.js
│   └── academy.js
├── database/
│   └── scans.sql
└── server/
    ├── app.js
    ├── db.js
    ├── package.json
    ├── package-lock.json
    ├── public/
    │   ├── login.html
    │   └── register.html
    ├── views/
    │   └── analyze.html
    ├── services/
    │   └── urlAnalyzer.js
    └── tests/
        └── urlAnalyzer.test.js
```

## Installation and Setup

### Prerequisites

Install the following software:

- Node.js and npm
- MySQL Server
- MySQL Workbench (recommended)
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/satnamkhokhar/phishguard.git
```

Navigate to the server directory:

```bash
cd phishguard/phishguard/server
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file inside the `server` directory.

Add the following configuration, replacing the placeholders with your local MySQL credentials:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=phishguard_db
SESSION_SECRET=replace_with_a_long_random_secret
```

Do not commit your `.env` file to GitHub.

### 4. Configure MySQL

Create a MySQL database named `phishguard_db`.

The application requires two tables:

**users**

Stores registered user accounts, including:

- `id`
- `name`
- `username`
- `email`
- `password_hash`

The `id` column must uniquely identify users. Usernames and email addresses should be unique.

**scans**

Stores saved URL analyses, including:

- `id`
- `user_id`
- `url`
- `hostname`
- `risk_score`
- `classification`
- `summary`
- `indicators`
- `created_at`
- `updated_at`

The `user_id` column references the corresponding user's ID.

The repository includes `database/scans.sql`, which defines the scans table and its foreign-key relationship.

**Setup note:** The current repository does not include a complete users-table creation script. Create the users table before running `scans.sql`. The database schema must match the fields expected by the application.

### 5. Start the Server

From the `server` directory:

```bash
npm start
```

Open the application at:

http://localhost:3000

New users can register an account and then log in to access PhishGuard.

## Application Routes

| Route | Description |
|---|---|
| `/` | Redirects to login or home |
| `/register.html` | User registration |
| `/login.html` | User login |
| `/index.html` | Home page |
| `/about.html` | About page |
| `/analyze` | URL analyzer |
| `/academy` | PhishGuard Academy |
| `/dashboard` | User dashboard |
| `/history` | Saved scan history |
| `/scans/:id` | View a saved scan |
| `/scans/:id/edit` | Edit a saved scan |
| `/profile` | User profile |
| `/logout` | End the active session |

Most application pages require authentication.

## Testing

PhishGuard includes automated tests for the URL analysis engine.

From the `server` directory, run:

```bash
npm test
```

The tests cover:

1. Basic HTTPS URL analysis
2. HTTP connection detection
3. IP-address hostname detection
4. Suspicious keyword detection
5. Empty URL rejection
6. Unsupported protocol rejection
7. Embedded credential rejection
8. Risk score boundaries
9. Preservation of submitted URLs

The application can also be manually tested by registering multiple accounts, creating saved scans, editing and deleting scans, and verifying that users cannot access another account's records.

## Security Considerations

PhishGuard implements several security measures:

- Salted password hashing
- Session-based authentication
- Protected application routes
- Account-specific database queries
- Parameterized SQL statements
- Server-side URL validation
- HTML escaping for dynamically rendered user content
- HTTP-only session cookies
- Login session regeneration

However, PhishGuard is primarily an academic application intended for local development and demonstration.

Additional measures would be required before production deployment, including:

- CSRF protection
- Login rate limiting
- HTTPS and secure cookies
- A persistent production session store
- Additional security headers
- More comprehensive integration and security testing

## Project Summary

PhishGuard demonstrates the integration of frontend development, backend APIs and routes, relational databases, authentication, session management, CRUD operations, and automated testing.

The project combines practical web development concepts with cybersecurity education, allowing users to analyze suspicious URLs while learning how to recognize common phishing techniques.

## Author

**Satnam Singh Khokhar**

B.S. Computer Science — Georgia State University

GitHub: https://github.com/satnamkhokhar

Project Repository: https://github.com/satnamkhokhar/phishguard