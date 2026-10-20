/*
    PhishGuard MySQL Database Connection

    Connects to the MySQL database and retrieves
    the dummy users stored in the users table.
*/

// Load database credentials from the .env file.
require("dotenv").config();

const mysql = require("mysql2/promise");

async function connectToDatabase() {
    try {
        // Establish a connection to the MySQL database.
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            port: Number(process.env.DB_PORT || 3306)
        });

        console.log("Connected to MySQL successfully!");

        // Retrieve the users from the database.
        const [rows] = await connection.execute(
            "SELECT id, name, email, created_at FROM users"
        );

        console.table(rows);

        // Close the connection after retrieving the data.
        await connection.end();

    } catch (error) {
        console.error("Database connection failed:", error.message);
        process.exitCode = 1;
    }
}

// Run the connection test.
connectToDatabase();