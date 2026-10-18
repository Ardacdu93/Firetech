const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const port = Number(process.env.PORT || 3000);
const jwtSecret = process.env.JWT_SECRET;
const databaseUrl = process.env.DATABASE_URL;

if (!jwtSecret || jwtSecret.length < 32) {
  throw new Error("Set JWT_SECRET to a random secret of at least 32 characters.");
}
if (!databaseUrl) {
  throw new Error("Set DATABASE_URL to your Render PostgreSQL connection string.");
}

const pool = new Pool({
  connectionString: databaseUrl,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

const allowedOrigin = process.env.CORS_ORIGIN;
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    // Non-browser clients may not send Origin. If configured, only allow the app's
    // explicitly configured origin; Electron file:// origins may serialize as null.
    if (!allowedOrigin || !origin || origin === allowedOrigin || origin === "null") {
      return callback(null, true);
    }
    return callback(new Error("Origin not allowed by CORS"));
  }
}));
app.use(express.json({ limit: "20kb" }));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false }));

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

function createToken(user) {
  return jwt.sign(
    { sub: String(user.id), username: user.username },
    jwtSecret,
    { expiresIn: "7d", issuer: "firetech" }
  );
}

function requireAuth(req, res, next) {
  const header = req.get("authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: "Connexion requise." });
  try {
    req.auth = jwt.verify(match[1], jwtSecret, { issuer: "firetech" });
    next();
  } catch {
    return res.status(401).json({ error: "Session invalide ou expirée." });
  }
}

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "FireTech Accounts" }));

app.post("/api/accounts/register", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Adresse e-mail invalide." });
    }
    if (!/^[a-zA-Z0-9_-]{3,24}$/.test(username)) {
      return res.status(400).json({ error: "Le pseudo doit contenir 3 à 24 caractères (lettres, chiffres, _ ou -)." });
    }
    if (password.length < 10 || password.length > 200) {
      return res.status(400).json({ error: "Le mot de passe doit contenir au moins 10 caractères." });
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users(email, username, password_hash) VALUES($1, $2, $3) RETURNING id, email, username, created_at",
      [email, username, passwordHash]
    );
    const user = result.rows[0];
    return res.status(201).json({ token: createToken(user), user });
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "Cet e-mail ou ce pseudo est déjà utilisé." });
    console.error("Registration error:", error);
    return res.status(500).json({ error: "Erreur interne du serveur." });
  }
});

app.post("/api/accounts/login", async (req, res) => {
  try {
    const identifier = String(req.body.identifier || "").trim();
    const password = String(req.body.password || "");
    if (!identifier || !password) return res.status(400).json({ error: "Remplis les champs." });
    const result = await pool.query(
      "SELECT id, email, username, password_hash, created_at FROM users WHERE lower(email)=lower($1) OR lower(username)=lower($1) LIMIT 1",
      [identifier]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Identifiants incorrects." });
    }
    return res.json({
      token: createToken(user),
      user: { id: user.id, email: user.email, username: user.username, created_at: user.created_at }
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ error: "Erreur interne du serveur." });
  }
});

app.get("/api/accounts/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, email, username, created_at FROM users WHERE id=$1",
      [req.auth.sub]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Compte introuvable." });
    return res.json({ user: result.rows[0] });
  } catch (error) {
    console.error("Account lookup error:", error);
    return res.status(500).json({ error: "Erreur interne du serveur." });
  }
});

app.use((error, _req, res, _next) => {
  if (error.message === "Origin not allowed by CORS") {
    return res.status(403).json({ error: "Origine non autorisée." });
  }
  console.error(error);
  return res.status(500).json({ error: "Erreur interne du serveur." });
});

initializeDatabase().then(() => {
  app.listen(port, "0.0.0.0", () => console.log(`FireTech account API listening on ${port}`));
}).catch(error => {
  console.error("Database initialization failed:", error);
  process.exit(1);
});
