const bcrypt = require('bcrypt');
const express = require('express');
const path = require('path');
const mysql = require('mysql');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);

  
const app = express();
const port = process.env.PORT || 3019;

// Extract database connection details from the JAWSDB_URL environment variable
const dbUrl = new URL(process.env.JAWSDB_URL);


app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const dbOptions = {
    host: dbUrl.hostname,
    port: dbUrl.port,
    user: dbUrl.username,
    password: dbUrl.password,
    database: dbUrl.pathname.substr(1) // Removing the leading slash
};

// Create the MySQL connection pool
const pool = mysql.createPool(dbOptions);
const sessionStore = new MySQLStore(dbOptions);

app.use(session({
    key: 'session_cookie_name',
    secret: process.env.SESSION_SECRET || 'fallbackSecretKey',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: true, // Set to true if using https
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Check and create tables if they don't exist
const createUserTableQuery = `
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    api_calls_made INT DEFAULT 0,
    is_admin BOOLEAN DEFAULT FALSE
)`;
pool.query(createUserTableQuery, (error, results) => {
    if (error) throw error;
    console.log("User table checked/created.");
});

app.use(express.urlencoded({ extended: true }));

app.use(express.json());

// CORS and Content Security Policy middleware
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none';");

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    } else {
        next();
    }
});


let fetch;
import('node-fetch').then(({ default: nodeFetch }) => {
  fetch = nodeFetch;
});


  
  // Middleware to verify if a user is logged in
const verifySession = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).send('Access Denied: You are not logged in');
    }
    next();
};

// Middleware to verify if a user is logged in and an admin
const verifyAdmin = (req, res, next) => {
    if (!req.session.userId || !req.session.isAdmin) {
        return res.status(403).send('Unauthorized');
    }
    next();
};

// Routes
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.post('/register', (req, res) => {
    const { email, password } = req.body;

    // Hash the password
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
            res.status(500).send('Error hashing password');
            return;
        }

        const user = { email, password: hashedPassword };

        pool.query('INSERT INTO users SET ?', user, (err, result) => {
            if (err) {
                res.status(500).send('Error registering user');
                return;
            }
            console.log('User registered');
            res.redirect('/login');
        });
    });
});


app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  pool.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).send('Error finding user');
    if (results.length > 0) {
      const user = results[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) return res.status(500).send('Error comparing passwords');
        if (isMatch) {
          // Set session information
          req.session.userId = user.id;
          req.session.isAdmin = Boolean(user.is_admin); // Ensure boolean conversion
          res.redirect('/protected');
        } else {
          res.send('Incorrect password');
        }
      });
    } else {
      res.send('Email not registered');
    }
  });
});



app.post('/generate-quote', async (req, res) => {
    const userId = req.session.userId;
    if (!userId) {
        return res.status(401).send('Unauthorized');
    }

    // Check if the user has exceeded the free API call limit
    pool.query('SELECT api_calls_made FROM users WHERE id = ?', [userId], async (error, results) => {
        if (error || results.length === 0) {
            return res.status(500).send('Error fetching user data');
        }

        let { api_calls_made } = results[0];
        if (api_calls_made >= 20) {
            // User has exceeded the free API call limit
            return res.json({ message: "You have maxed out your free API calls.", continue: true });
        } else {
            // Proceed with calling the HuggingFace API
            try {
                const data = {
                    inputs: req.body.prompt, // Assuming 'prompt' is passed in the request body
                    parameters: {} // Add any required parameters here
                };

                const hfResponse = await fetch("https://nckuxizqlfd71lmx.us-east-1.aws.endpoints.huggingface.cloud", {
                    method: "POST",
                    headers: {
                        "Accept": "application/json",
                        "Authorization": "Bearer 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",
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify(data)
                });

                if (!hfResponse.ok) throw new Error(`HuggingFace server error: ${hfResponse.statusText}`);
                
                const hfResult = await hfResponse.json();
                // Increment API call count
                pool.query('UPDATE users SET api_calls_made = api_calls_made + 1 WHERE id = ?', [userId]);
                res.json(hfResult);
            } catch (error) {
                console.error('Error calling HuggingFace API:', error);
                res.status(500).send('Error fetching quote.');
            }
        }
    });
});

app.get('/protected', verifySession, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'protected.html'));
});

app.get('/quote_generator', verifySession, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'quote_generator.html'));
});

app.get('/api/admin/usage', verifyAdmin, (req, res) => {
    pool.query('SELECT email, api_calls_made FROM users', (error, results) => {
        if (error) return res.status(500).send('Error fetching data');
        res.json(results);
    });
});

app.get('/api/usage', verifySession, (req, res) => {
    const userId = req.session.userId;
    pool.query('SELECT api_calls_made FROM users WHERE id = ?', [userId], (error, results) => {
        if (error) {
            return res.status(500).send('Error fetching API usage data');
        }
        if (results.length > 0) {
            const usage = results[0].api_calls_made;
            res.json({ apiCallsMade: usage });
        } else {
            res.status(404).send('User not found');
        }
    });
});


// Start server
app.listen(port, () => {
    console.log(`Server running on ${port}`);
});
