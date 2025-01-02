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
		password TEXT,
		is_admin INTEGER
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
    "INSERT OR IGNORE INTO Users (id, username, password, is_admin) VALUES (1, ?, ?, 1)",
    "admin",
    pword,
  );
});

app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", "src/views");
app.use(express.static("src/public"));

app.get("/logout", (req, res) => {
  res.clearCookie("Authorization");
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("layout", {
    title: "Login",
    body: `
		<h1>Log In to the Gary Library</h1>
		<form method="POST" action="/login">
			<label for="username">Username</label>
			<input type="text" name="username" />
			<label for="password">Password</label>
			<input type="password" name="password" />
			<button type="submit">Login</button>
		</form>
`,
  });
});

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

    db.all(
      "SELECT user, is_admin FROM Sessions s JOIN Users u ON s.user = u.id WHERE s.id = ?",
      sessionId,
      (err, rows) => {
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
        req.isAdmin = Boolean(rows[0].is_admin);

        next();
      },
    );
  }
});

app.use((req, res, next) => {
  req.hxRequest = req.headers["hx-request"] === "true";
  next();
});

app.get("/", (req, res) => {
  res.render("layout", {
    title: "Home",
    body: '<h1>Welcome to the Gary Library</h1><p hx-get="/items" hx-trigger="load"><a href="/items">View Items</a>',
  });
});

app.get("/items", (req, res) => {
  const { search } = req.query;
  console.log("###", search);
  const query = `SELECT * FROM items_view WHERE ${
    search ? "name LIKE ?" : "1=1"
  }`;
  db.all(query, search ? [`%${search}%`] : [], (err, rows) => {
    if (err) {
      console.error("Error getting items", err);
      res.sendStatus(500);
    } else {
      const searchForm = `<form action="/items" method="GET">
        <label for="search">Search</label>
        <input
          type="search"
          name="search"
          hx-get="/items"
          hx-trigger="keyup changed delay:500ms, search"
          hx-target="#item-table"
          hx-swap="outerHTML"
        />
      </form>`;

      const html = `<table id="item-table">
          <tr>
            <th>Name</th>
            <th>Format</th>
            <th>Owner</th>
          </tr>
          ${rows
            .map(
              (row) =>
                `<tr><td><a href="/items/${row.id}">${row.name}</a></td><td>${row.format}</td><td>${row.owner}</td></tr>`,
            )
            .join("")}
        </table>
      </form>`;
      req.hxRequest
        ? res.send(html)
        : res.render("layout", { title: "Items", body: searchForm + html });
    }
  });
});

app.get("/items/create", (req, res) => {
  res.render("layout", {
    title: "Create Item",
    body: `
    <form hx-post="/items">
      <label for="name">Name</label>
      <input type="text" name="name" />
      <label for="description">Description</label>
      <textarea name="description"></textarea>
      <label for="format">Format</label>
      <select name="format">
        <option value="">-- Select Format --</option>
        <option value="BLURAY">Blu-Ray</option>
        <option value="BOOK">Book</option>
        <option value="CD">CD</option>
        <option value="DVD">DVD</option>
        <option value="EPUB">EPub</option>
        <option value="MP3">MP3</option>
        <option value="MP4">MP4</option>
        <option value="PDF">PDF</option>
        <option value="VINYL">Vinyl</option>
      </select>
      <button type="submit">Create new Item</button>
    </form>`,
  });
});

app.get("/items/:id", (req, res) => {
  db.all(
    "SELECT * FROM items_view WHERE id = ?",
    req.params.id,
    (err, rows) => {
      if (err) {
        console.error("Could not fetch item", err);
        return;
      }
      if (rows.length === 0) {
        res.sendStatus(404);
        return;
      }
      const item = rows[0];
      res.send(`<div><h1>${item.name}</h1><p>${item.description}</p></div>`);
    },
  );
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

/** @type {import("express").RequestHandler} */
const isAdmin = (req, res, next) => {
  if (!req.isAdmin) {
    res.sendStatus(403);
  } else {
    next();
  }
};

app.get("/users", isAdmin, (req, res) => {
  db.all("SELECT * FROM Users", (err, rows) => {
    if (err) {
      console.error("Could not fetch users", err);
      res.sendStatus(500);
      return;
    }
    const table = `<table><tr><th>Username</th><th>Is Admin</th><th></th></tr>${rows.map(
      (user) =>
        `<tr><td>${user.username}</td><td>${user.is_admin}</td><td><button hx-delete="/users/${user.id}">Delete</button</td></tr>`,
    ).join('')}</table>`;
		req.hxRequest ? res.send(table) : res.render('layout', { title: 'Users', body: table });
  });
});

app.get("/users/create", isAdmin, (req, res) => {
  res.render("layout", {
    title: "Create User",
    body: `
<form hx-post="/users">
			<label for="username">Username</label>
			<input type="text" name="username" />
			<label for="password">Password</label>
			<input type="password" name="password" />
			<button type="submit">Create User</button>
</form>
`,
  });
});

app.post("/users", isAdmin, (req, res) => {
  const { username } = req.body;
  const password = bcrypt.hashSync(req.body.password, 10);
  db.all(
    "INSERT INTO Users (username, password) VALUES (?, ?)",
    username,
    password,
    (err) => {
      if (err) {
        console.error("Could not create user", err);
      } else {
        res.setHeader("HX-Refresh", "true");
        res.sendStatus(201);
      }
    },
  );
});

app.delete('/users/:id', isAdmin, (req, res) => {
	db.run('DELETE FROM Users WHERE id = ?', req.params.id);
	res.setHeader('HX-Redirect', '/users');
	res.sendStatus(201);
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
