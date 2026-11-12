
# PhishGuard

PhishGuard is a full-stack web application being developed
to help users identify and understand potentially suspicious
website URLs.

This project is built for a Web Programming course and
demonstrates frontend development, backend authentication,
database integration, and session management.

## Technologies

- HTML5
- CSS3
- JavaScript
- Node.js
- Express.js
- MySQL
- express-session

## Current Features

- User registration
- User login with password hashing
- MySQL database integration
- Session-based authentication
- Protected pages
- User profile displaying the logged-in username
- Logout functionality
- Dark and light themes

## Planned Features

- URL phishing indicator analysis
- Explainable risk scoring
- Saved URL scan history
- Create, Read, Update, and Delete operations
- Dashboard with scan statistics

## Installation

### 1. Clone the repository

git clone https://github.com/satnamkhokhar/phishguard.git

### 2. Open the application folder

cd phishguard/phishguard/server

### 3. Install dependencies

npm install

### 4. Configure environment variables

Copy `.env.example` to `.env` inside the server folder.

Set the following variables:

- DB_HOST
- DB_PORT
- DB_USER
- DB_PASSWORD
- DB_NAME
- SESSION_SECRET

### 5. Prepare MySQL

Create a database named `phishguard_db` and configure
the existing users table.

A reproducible database setup script will be added
during the database development phase.

### 6. Start the application

npm start

Visit http://localhost:3000

## Authentication

PhishGuard uses server-side sessions to manage user
authentication.

Users must log in to access protected pages. The user's
ID and username are stored in the session after a
successful login.

Logging out destroys the active session.

## Project Status

The authentication and session-management foundation
is implemented.

URL analysis and scan-history CRUD functionality are
planned for the next development phases.

## Author

Satnam Singh Khokhar

GitHub: https://github.com/satnamkhokhar
