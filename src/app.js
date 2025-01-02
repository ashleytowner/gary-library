const sqlite3 = require("sqlite3");
const db = new sqlite3.Database("./database.db");
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS Items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		description TEXT,
		format TEXT,
		owner INTEGER,
		FOREIGN KEY (owner) REFERENCES Users(id)
	)`);
  db.run(`CREATE TABLE IF NOT EXISTS Users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT,
		password TEXT
	)`);
  db.run(`CREATE TABLE IF NOT EXISTS Movements (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		item INTEGER,
		origin INTEGER,
		destination INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (item) REFERENCES Items(id),
		FOREIGN KEY (origin) REFERENCES Users(id),
		FOREIGN KEY (destination) REFERENCES Users(id)
	)`);
  db.run(`CREATE TABLE IF NOT EXISTS Sessions (
		id TEXT PRIMARY KEY,
		user INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user) REFERENCES Users(id)
	)`);
	db.run(`CREATE VIEW IF NOT EXISTS items_view AS
		SELECT i.id as id, name, description, format, username as owner FROM Items i
		JOIN Users u ON i.owner = u.id`);
  const pword = bcrypt.hashSync("admin", 10);
  db.run(
    "INSERT OR IGNORE INTO Users (id, username, password) VALUES (1, ?, ?)",
    "admin",
    pword,
  );
});

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("src/public"));

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.all(
    "SELECT id, password FROM Users WHERE username = ?",
    username,
    (err, rows) => {
      if (err) {
        console.error("Error fetching user", err);
        return;
      }

      if (rows.length === 0) {
        return res.sendStatus(400);
      } else {
        const isMatchingPassword = bcrypt.compareSync(
          password,
          rows[0].password,
        );
        if (!isMatchingPassword) {
          return res.sendStatus(400);
        }
        crypto.randomBytes(127, (err, buf) => {
          if (err) {
            console.error("Error generating random bytes", err);
            res.sendStatus(500);
          } else {
            const id = buf.toString("base64");
            db.run(
              "INSERT INTO Sessions (id, user) VALUES (?, ?)",
              id,
              rows[0].id,
            );
            res.cookie("Authorization", id, { httpOnly: true });
          }
          res.redirect("/");
        });
      }
    },
  );
});

app.use((req, res, next) => {
  if (!req.cookies["Authorization"]) {
    res.redirect("/login");
  } else {
    const sessionId = req.cookies["Authorization"];

    db.all("SELECT * FROM Sessions WHERE id = ?", sessionId, (err, rows) => {
      if (err) {
        console.error("Error fetching session", err);
        res.sendStatus(500);
        return;
      }

      if (rows.length === 0) {
        res.sendStatus(401);
        return;
      }

      req.userId = rows[0].user;

      next();
    });
  }
});

app.use(express.static("src/private"));

app.get("/items", (req, res) => {
  db.all("SELECT * FROM items_view", (err, rows) => {
    if (err) {
      console.error("Error getting items", err);
      res.sendStatus(500);
    } else {
      const html = rows.map(
        (row) =>
          `<tr><td><a href="/items/${row.id}">${row.name}</a></td><td>${row.format}</td><td>${row.owner}</td></tr>`,
      );
      res.send(
        `<table><tr><th>Name</th><th>Format</th><th>Owner</th></tr>${html}</table>`,
      );
    }
  });
});

app.get("/items/:id", (req, res) => {
	db.all("SELECT * FROM items_view WHERE id = ?", req.params.id, (err, rows) => {
		if (err) {
			console.error('Could not fetch item', err);
			return;
		}
		if (rows.length === 0) {
			res.sendStatus(404);
			return;
		}
		const item = rows[0];
		res.send(`<div><h1>${item.name}</h1><p>${item.description}</p></div>`);
	});
});

app.post("/items", (req, res) => {
  const { name, description, format } = req.body;
  db.run(
    "INSERT INTO Items (name, description, format, owner) VALUES (?, ?, ?, ?)",
    name,
    description,
    format,
    req.userId,
    (err) => {
      if (err) {
        console.error("Failed to add Item", err);
        res.sendStatus(500);
      } else {
        res.sendStatus(201);
      }
    },
  );
});

app.listen(3000, () => {
  console.log("App listening on port 3000");
});

process.on("SIGINT", () => {
  if (db) {
    db.close((err) => {
      if (err) {
        console.error(err.message);
      } else {
        console.info("Database connection closed");
      }
      process.exit(0);
    });
  } else {
    console.info("No database connection to close");
    process.exit(0);
  }
});
