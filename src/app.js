const sqlite3 = require("sqlite3");
const db = new sqlite3.Database("./database.sqlite");
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const marked = require("marked");

const app = express();

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS Items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    owner INTEGER NOT NULL,
    FOREIGN KEY (owner) REFERENCES Users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS Sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    user INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user) REFERENCES Users(id)
  )`);
  db.run("CREATE INDEX IF NOT EXISTS idx_sessions_key ON Sessions(key)");
  db.run(`CREATE TABLE IF NOT EXISTS Requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL CHECK (action IN ('borrow', 'consult')),
    item INTEGER NOT NULL,
    user INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'rejected', 'approved')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (item) REFERENCES Items(id),
    FOREIGN KEY (user) REFERENCES Users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS Loans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item INTEGER NOT NULL,
    user INTEGER NOT NULL,
    loaned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    returned_at TIMESTAMP,
    FOREIGN KEY (item) REFERENCES Items(id),
    FOREIGN KEY (user) REFERENCES Users(id)
  )`);
  db.run(`CREATE VIEW IF NOT EXISTS v_items AS 
    SELECT
      i.*,
      u.username as owner_name,
      CASE WHEN l.loaned_at IS NULL THEN 1 ELSE 0 END as available
    FROM Items i 
    JOIN Users u ON i.owner = u.id
    LEFT JOIN Loans l ON i.id = l.item AND l.returned_at IS NULL;`);
  db.run(`CREATE TABLE IF NOT EXISTS ItemTags (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		item INTEGER NOT NULL,
		tag TEXT NOT NULL,
		value TEXT NOT NULL,
		FOREIGN KEY (item) REFERENCES Items(id)
	)`);
  db.run(
    "CREATE VIEW IF NOT EXISTS tags AS SELECT DISTINCT tag FROM ItemTags;",
  );
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

app.use((req, res, next) => {
  res.locals.loggedIn = false;
  res.locals.isAdmin = false;
  next();
});

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
              "INSERT INTO Sessions (key, user) VALUES (?, ?)",
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
      "SELECT user, is_admin FROM Sessions s JOIN Users u ON s.user = u.id WHERE s.key = ?",
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

        res.locals.userId = rows[0].user;
        res.locals.isAdmin = Boolean(rows[0].is_admin);
        res.locals.loggedIn = true;

        next();
      },
    );
  }
});

app.use((req, _res, next) => {
  req.hxRequest = req.headers["hx-request"] === "true";
  next();
});

app.get("/", (_req, res) => {
  const links = [
    '<a href="/items">View Items</a>',
    '<a href="/items/create">Add an Item</a>',
  ];
  if (res.locals.isAdmin) {
    links.push(
      ...[
        '<a href="/users">View Users</a>',
        '<a href="/users/create">Add a user</a>',
      ],
    );
  }
  res.render("layout", {
    title: "Home",
    body: `<h1>Welcome to the Gary Library</h1><p>${links.join(" • ")}</p>`,
  });
});

app.get("/items", (req, res) => {
  const { search } = req.query;
  const query = `SELECT * FROM v_items WHERE ${search ? "name LIKE ?" : "1=1"}`;
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

      const table =
        rows.length > 0
          ? `<table id="item-table">
          <tr>
            <th>Name</th>
            <th>Owner</th>
            <th>Available</th>
          </tr>
          ${rows
            .map(
              (row) =>
                `<tr><td><a href="/items/${row.id}">${row.name}</a></td><td>${
                  row.owner_name
                }</td><td>${
                  row.available ? "☑ Available" : "☒ Unavailable"
                }</td></tr>`,
            )
            .join("")}
        </table>
      </form>`
          : "<p>There are no items to display</p>";
      req.hxRequest
        ? res.send(table)
        : res.render("layout", {
            title: "Items",
            body:
              '<h1>Library Items</h1><p>Here you can view & search through all the items in the library</p><a class="button-like" href="/items/create">Add Item</a>' +
              searchForm +
              table,
          });
    }
  });
});

app.get("/items/create", (_req, res) => {
  res.render("layout", {
    title: "Create Item",
    body: `
    <form hx-boost="true" method="POST" action="/items">
      <label for="name">Name</label>
      <input type="text" name="name" />
      <label for="description">Description</label>
      <textarea name="description"></textarea>
      <button type="submit">Create new Item</button>
    </form>`,
  });
});

app.get("/items/:id", (req, res) => {
  db.all(
    `SELECT i.*, l.id as loan_id, u.username
    FROM v_items i 
    LEFT JOIN Loans l ON i.id = l.item 
    LEFT JOIN Users u ON l.user = u.id
    WHERE i.id = ? 
    ORDER BY l.loaned_at DESC;`,
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
      const isOwner = item.owner === res.locals.userId;
      let html = `<div>
      <h1>${item.name}</h1>
      <p>${marked.parse(item.description)}</p>
      <p>${
        item.available
          ? "☑ Available"
          : `☒ Unavailable (On Loan to ${item.username})`
      }</p>
      ${
        isOwner && !item.available
          ? `<button hx-put="/loan/${item.loan_id}/return" hx-swap="outerHTML">Mark As Returned</button>`
          : ""
      }
      ${
        !isOwner
          ? `<button hx-post="/items/${item.id}/request">Request to Borrow</button>`
          : ""
      }
    </div>`;
      db.all(
        "SELECT * FROM ItemTags WHERE item = ?",
        req.params.id,
        (err, rows) => {
          html += `<h2>Tags</h2><button hx-get="/items/${req.params.id}/tag" hx-select="#page_body > *" hx-swap="outerHTML">Add Tag</button>`;
          if (err) {
            console.error("Could not get item tags", err);
          } else if (rows.length > 0) {
            html += `${rows
              .map((tag) => `<p>${tag.tag}: ${tag.value}</p>`)
              .join("")}`;
          }
          db.all(
            'SELECT r.*, u.username FROM Requests r JOIN Users u ON r.user = u.id WHERE item = ? AND status = "pending" ORDER BY created_at DESC',
            item.id,
            (err, rows) => {
              if (err) {
                console.error("Could not fetch requests for item", err);
              } else if (rows.length > 0) {
                html += `<h2>Requests</h2>
            <table>
              <tr>
                <th>User</th>
                <th>Date</th>
                ${isOwner ? "<th>Actions</th>" : ""}
              </tr>
              ${rows
                .map(
                  (row) =>
                    `<tr id="request-${row.id}">
                    <td>${row.username}</td>
                    <td>${row.created_at}</td>
                    ${
                      isOwner
                        ? `<td>
                            <button hx-target="#request-${row.id}" hx-put="/requests/${row.id}/approve">
                              Approve</button
                            ><button hx-target="#request-${row.id}" hx-put="/requests/${row.id}/reject">
                              Reject
                            </button>
                          </td>`
                        : ""
                    }
                  </tr>`,
                )
                .join("")}
            </table>`;
              }
              res.render("layout", { title: item.name, body: html });
            },
          );
        },
      );
    },
  );
});

app.post("/items/:id/request", (req, res) => {
  let { action } = req.body;
  if (!action) {
    // res
    //   .status(400)
    //   .send("You must specify an action, either Borrow or Consult");
    // return;
    action = "borrow";
  }
  db.get("SELECT * FROM items WHERE id = ?", req.params.id, (err, item) => {
    if (err) {
      console.error("Cannot fetch item", err);
      res.sendStatus(500);
      return;
    }
    if (!item) {
      res.sendStatus(404);
      return;
    }
    if (item.owner === res.locals.userId) {
      res.status(400).send("You cannot request your own item!");
      return;
    }
    db.get(
      "SELECT * FROM Requests WHERE user = ? AND item = ? ORDER BY created_at DESC",
      res.locals.userId,
      req.params.id,
      (err, request) => {
        if (err) {
          console.error("Could not fetch requests", err);
          res.sendStatus(500);
          return;
        }
        if (request && request.status === "pending") {
          res
            .status(400)
            .send("You already have a pending request for this item");
          return;
        }
        db.run(
          'INSERT INTO Requests (action, item, user, status) VALUES (?, ?, ?, "pending")',
          action,
          req.params.id,
          res.locals.userId,
          (err) => {
            if (err) {
              console.error("Could not create a request!", err);
              res.sendStatus(500);
              return;
            }
            res.setHeader("HX-Refresh", "true");
            res.sendStatus(201);
          },
        );
      },
    );
  });
});

app.put("/requests/:id/approve", (req, res) => {
  db.get(
    "SELECT r.*, i.owner FROM Requests r JOIN Items i ON r.item = i.id WHERE r.id = ?",
    req.params.id,
    (err, row) => {
      if (err) {
        console.error("Could not get request", err);
        res.sendStatus(500);
        return;
      }
      if (!row) {
        res.sendStatus(404);
        return;
      }
      if (row.owner !== res.locals.userId) {
        res.sendStatus(403);
        return;
      }
      // TODO: Add a check to see if it is currently lent out, as you can't approve
      // a borrow if it is already on loan.
      db.serialize(() => {
        try {
          db.run("BEGIN TRANSACTION");

          db.run(
            'UPDATE Requests SET status = "approved" WHERE id = ?',
            req.params.id,
          );

          db.run(
            "INSERT INTO Loans (item, user) VALUES (?, ?)",
            row.item,
            row.user,
          );

          db.run("COMMIT");

          res.setHeader("HX-Refresh", "true");
          res.status(201).send("Successfully Approved");
        } catch (err) {
          console.error("Could not approve the borrow", err);
          db.run("ROLLBACK");
          res.sendStatus(500);
        }
      });
    },
  );
});

app.put("/loan/:id/return", (req, res) => {
  db.get(
    "SELECT l.*, i.owner FROM Loans l JOIN Items i ON l.item = i.id WHERE l.id = ?",
    req.params.id,
    (err, row) => {
      if (err) {
        console.error("Cannot return item", err);
        res.sendStatus(500);
        return;
      }
      if (!row) {
        res.sendStatus(404);
        return;
      }
      if (row.owner !== res.locals.userId) {
        res.sendStatus(403);
        return;
      }
      db.run(
        "UPDATE Loans SET returned_at = CURRENT_TIMESTAMP WHERE id = ?",
        req.params.id,
        (err) => {
          if (err) {
            console.error("Could not update timestamp");
            res.sendStatus(500);
            return;
          }
          res.setHeader("HX-Refresh", "true");
          res.status(201).send("Successfully Returned");
        },
      );
    },
  );
});

app.put("/requests/:id/reject", (req, res) => {
  db.get(
    "SELECT r.*, i.owner FROM Requests r JOIN Items i ON r.item = i.id WHERE r.id = ?",
    req.params.id,
    (err, row) => {
      if (err) {
        console.error("Could not get request", err);
        res.sendStatus(500);
        return;
      }
      if (!row) {
        res.sendStatus(404);
        return;
      }
      if (row.owner !== res.locals.userId) {
        res.sendStatus(403);
        return;
      }
      db.run(
        'UPDATE Requests SET status = "rejected" WHERE id = ?',
        req.params.id,
        (err) => {
          if (err) {
            console.error("Could not reject request");
            res.sendStatus(500);
            return;
          }
          res.setHeader("HX-Refresh", "true");
          res.status(201).send("Successfully Rejected");
        },
      );
    },
  );
});

app.post("/items", (req, res) => {
  const { name, description } = req.body;
  db.run(
    "INSERT INTO Items (name, description, owner) VALUES (?, ?, ?)",
    name,
    description,
    res.locals.userId,
    (err) => {
      if (err) {
        console.error("Failed to add Item", err);
        res.sendStatus(500);
      } else {
        res.setHeader("HX-Redirect", "/items");
        res.sendStatus(201);
      }
    },
  );
});

app.get("/items/:id/tag", (req, res) => {
  const html = `<form hx-post="/tags">
    <datalist
      id="tag-names"
      hx-get="/tags/options"
      hx-trigger="load"
    ></datalist>
    <datalist id="tag-values"></datalist>
    <input name="item" value="${req.params.id}" hidden />
    <label for="tag">Tag Name</label>
    <input
      list="tag-names"
      type="text"
      name="tag"
      hx-get="/tags/values/options"
      hx-trigger="change"
      hx-target="#tag-values"
    />
    <label for="value">Tag Value</label>
    <input list="tag-values" name="value" />
    <button type="Submit">Tag Item</button>
  </form>`;
  res.render("layout", { title: "Tag Item", body: html });
});

app.get("/tags/options", (req, res) => {
  db.all("SELECT * FROM tags", (err, rows) => {
    if (err) {
      console.error("Could not get tags", err);
      return res.sendStatus(500);
    }
    const opts = rows.map(
      (row) =>
        `<option label="${row.tag}" value="${row.tag}">${row.tag}</option>`,
    );
    res.send(opts.join(""));
  });
});

app.get("/tags/values/options", (req, res) => {
  const tag = req.query.tag;
  if (!tag) {
    return res.status(400).send("Tag is required");
  }
  db.all(
    "SELECT DISTINCT value FROM ItemTags WHERE tag = ?",
    tag,
    (err, rows) => {
      if (err) {
        console.error("Could not get tag values", err);
        return res.sendStatus(500);
      }
      const opts = rows.map(
        (row) =>
          `<option label="${row.value}" value="${row.value}">${row.value}</option>`,
      );
      res.send(opts.join(""));
    },
  );
});

app.post("/tags", (req, res) => {
  const { item, tag, value } = req.body;
  if (!item) {
    return res.status(400).send("Item ID is Required");
  }
  if (!tag) {
    return res.status(400).send("Tag name is Required");
  }
  if (tag.startsWith("--")) {
    return res.status(400).send("Invalid tag Name");
  }
  if (!value) {
    return res.status(400).send("Tag value is Required");
  }
  db.run(
    "INSERT INTO ItemTags (item, tag, value) VALUES (?, ?, ?)",
    item,
    tag,
    value,
    (err) => {
      if (err) {
        console.error("Could not add tag", err);
        return res.sendStatus(500);
      }
      res.setHeader("HX-Redirect", `/items/${item}`);
      res.sendStatus(201);
    },
  );
});

app.get("/profile", (_req, res) => {
  db.get("SELECT * FROM Users WHERE id = ?", res.locals.userId, (err, row) => {
    if (err) {
      console.error("Could not fetch user", err);
      res.sendStatus(500);
      return;
    }
    if (!row) {
      res.sendStatus(404);
      return;
    }
    res.render("layout", {
      title: "Profile",
      body: `<h1>Hello, ${row.username}</h1>
        <form hx-put="/users/update-password">
          <label for="new_password">New Password</label>
          <input type="password" name="new_password" />
          <button type="submit">Change Password</button>
        </form>`,
    });
  });
});

/** @type {import("express").RequestHandler} */
const isAdmin = (_req, res, next) => {
  if (!res.locals.isAdmin) {
    res.sendStatus(403);
  } else {
    next();
  }
};

app.get("/sessions", isAdmin, (req, res) => {
  db.all(
    "SELECT s.*, u.username FROM Sessions s JOIN Users u ON s.user = u.id",
    (err, rows) => {
      console.log(rows);
      if (err) {
        console.error("Could not fetch sessions", err);
        return res.sendStatus(500);
      }
      const table = `<table><tr><th>Session</th><th>User</th><th>Created</th><th>Action</th></tr>${rows
        .map((session) => {
          return `<tr><td>${session.key.substring(0, 8)}...</td><td>${
            session.username
          }</td><td>${
            session.created_at
          }</td><td><button hx-delete="/sessions/${
            session.id
          }">Invalidate</button></td></tr>`;
        })
        .join("")}`;
      res.render("layout", { title: "Sessions", body: table });
    },
  );
});

app.delete("/sessions/:id", isAdmin, (req, res) => {
  db.run("DELETE FROM Sessions WHERE id = ?", req.params.id, (err) => {
    if (err) {
      console.error("Could not delete session", err);
      return res.sendStatus(500);
    }
    res.setHeader("HX-Refresh", "true");
    res.status(201).send("Invalidated Session");
  });
});

app.get("/users", isAdmin, (req, res) => {
  db.all("SELECT * FROM Users", (err, rows) => {
    if (err) {
      console.error("Could not fetch users", err);
      res.sendStatus(500);
      return;
    }
    const table = `<table><tr><th>Username</th><th>Is Admin</th><th></th></tr>${rows
      .map(
        (user) =>
          `<tr><td>${user.username}</td><td>${user.is_admin}</td><td><button hx-delete="/users/${user.id}">Delete</button</td></tr>`,
      )
      .join("")}</table>`;
    req.hxRequest
      ? res.send(table)
      : res.render("layout", {
          title: "Users",
          body: '<a href="/users/create">Add a user</a>' + table,
        });
  });
});

app.get("/users/create", isAdmin, (_req, res) => {
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

app.put("/users/update-password", (req, res) => {
  const { new_password } = req.body;
  if (!new_password) {
    res.sendStatus(400);
    return;
  }
  db.run(
    "UPDATE Users SET password=? WHERE id = ?",
    bcrypt.hashSync(new_password, 10),
    res.locals.userId,
    (err) => {
      if (err) {
        console.error("Could not update password", err);
        res.sendStatus(500);
        return;
      }
      res.status(201).send("Password Updated Successfully!");
    },
  );
});

app.delete("/users/:id", isAdmin, (req, res) => {
  db.run("DELETE FROM Users WHERE id = ?", req.params.id);
  res.setHeader("HX-Redirect", "/users");
  res.sendStatus(201);
});

app.listen(1234, () => {
  console.log("App listening on port 1234");
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
