const sqlite3 = require("sqlite3");
const db = new sqlite3.Database("./database.sqlite");
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const marked = require("marked");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { config } = require("dotenv");
const sanitize = require("sanitize-html");

config();

const app = express();

const upload = multer({ dest: path.join(__dirname, "public/img") });

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS Items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    image TEXT,
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
  db.run(`CREATE TABLE IF NOT EXISTS Comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user NUMBER NOT NULL,
		item NUMBER NOT NULL,
		content TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user) REFERENCES Users(id),
		FOREIGN KEY (item) REFERENCES Items(id)
	)`);
  db.run(
    "CREATE VIEW IF NOT EXISTS tags AS SELECT DISTINCT tag FROM ItemTags;",
  );
  db.run(`CREATE VIEW IF NOT EXISTS pending_requests 
    AS SELECT r.id id, i.id item, u.username borrower, i.name item_name, i.owner 
    FROM Requests r 
    JOIN Items i ON r.item = i.id 
    JOIN Users u ON r. user = u.id 
    WHERE status = 'pending'
    ORDER BY r.created_at ASC`);
  const pword = bcrypt.hashSync("admin", 10);
  db.run(
    "INSERT OR IGNORE INTO Users (id, username, password, is_admin) VALUES (1, ?, ?, 1)",
    "admin",
    pword,
  );
});

app.use(cookieParser());
app.set("view engine", "ejs");
app.set("views", "src/views");
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.locals.loggedIn = false;
  res.locals.isAdmin = false;
  res.locals.sanitize = sanitize;
  next();
});

app.get("/logout", (req, res) => {
  const sessionId = req.cookies["Authorization"];
  db.run("DELETE FROM Sessions WHERE key = ?", sessionId, (err) => {
    console.error("Failed to delete session", err);
  });
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
            res.cookie("Authorization", id, {
              maxAge: 86400000,
              httpOnly: true,
              secure: process.env.NODE_ENV !== "develop",
            });
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
      "SELECT user, is_admin, created_at FROM Sessions s JOIN Users u ON s.user = u.id WHERE s.key = ?",
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

        if (
          Number(new Date(rows[0].created_at)) + 86400000 <
          Number(new Date())
        ) {
          db.run("DELETE FROM Sessions WHERE key = ?", sessionId, (err) => {
            if (err) {
              console.error("Could not delete expired session", err);
            }
          });
          return res.redirect("/logout");
        }

        res.locals.userId = rows[0].user;
        res.locals.isAdmin = Boolean(rows[0].is_admin);
        res.locals.loggedIn = true;

        db.get(
          "SELECT COUNT(*) as count FROM pending_requests WHERE owner = ?",
          res.locals.userId,
          (err, row) => {
            if (err) {
              console.error("Could not get pending_requests for user", err);
            } else {
              res.locals.pendingRequestCount = row.count;
            }
            next();
          },
        );
      },
    );
  }
});

app.use((req, _res, next) => {
  req.hxRequest = req.headers["hx-request"] === "true";
  next();
});

app.get("/", (_req, res) => {
  res.render("layout", {
    title: "Home",
    body: `<h1>Welcome to the Gary Library</h1>
      <a href="/pending-requests"
        >You have ${res.locals.pendingRequestCount} pending request(s)</a
      >`,
  });
});

app.get("/pending-requests", (_req, res) => {
  db.all(
    "SELECT * FROM pending_requests WHERE owner = ?",
    res.locals.userId,
    (err, pendingRequests) => {
      if (err) {
        console.error("Could not get pending requests", err);
        return res.sendStatus(500);
      }
      res.render("pending-requests", {
        title: "Pending Requests",
        pendingRequests,
      });
    },
  );
});

app.get("/items", (req, res) => {
  const search = (req.query.search || "").trim();
  const searchTerms = search ? [search, ...search.split(" ")] : [];

  const page = req.query.page ? Number(req.query.page) : 1;
  const PAGE_SIZE = 25;
  const offset = (page - 1) * PAGE_SIZE;

  const subquery = search
    ? searchTerms
        .map((_) => {
          return `
            SELECT i.* FROM v_items i WHERE i.name LIKE ?
            UNION ALL
            SELECT i.* FROM v_items i WHERE i.description LIKE ?
            UNION ALL
            SELECT i.* FROM v_items i LEFT JOIN ItemTags it ON i.id = it.item WHERE it.value LIKE ?
          `;
        })
        .join(" UNION ALL ")
    : "SELECT * FROM v_items";

  const mainQuery = `SELECT COUNT(id) count, * FROM (${subquery}) GROUP BY id ORDER BY count DESC, name ASC`;

  const countQuery = `SELECT COUNT(*) total FROM (${mainQuery})`;

  const limitedQuery = `SELECT * FROM (${mainQuery}) LIMIT ${PAGE_SIZE} OFFSET ?`;

  const parameters = search
    ? searchTerms.map((term) => [`%${term}%`, `%${term}%`, `%${term}%`]).flat()
    : [];

  db.get(countQuery, ...parameters, (err, row) => {
    if (err) {
      console.error("Could not count results", err);
      return res.sendStatus(500);
    }
    const { total } = row;
    const pageCount = Math.ceil(total / PAGE_SIZE);

    db.all(limitedQuery, ...parameters, offset, (err, items) => {
      if (err) {
        console.error("Error getting items", err);
        return res.sendStatus(500);
      }
      res.render("item-list", {
        title: "Items",
        items,
        search,
        page,
        pageCount,
      });
    });
  });
});

app.get("/items/create", (_req, res) => {
  res.render("edit-item", {
    title: "Create Item",
    showImage: true,
    method: "post",
    item: {},
  });
});

app.put("/items/:id", (req, res) => {
  const { name, description } = req.body;
  db.get("SELECT * FROM Items WHERE id = ?", req.params.id, (err, row) => {
    if (err) {
      console.error("Could not get item", err);
      return res.sendStatus(500);
    }
    if (row.owner !== res.locals.userId && !res.locals.isAdmin) {
      return res.sendStatus(403);
    }
    db.run(
      "UPDATE Items SET name = ?, description = ? WHERE id = ?",
      name,
      description,
      req.params.id,
      (err) => {
        if (err) {
          console.error("Could not update item", err);
          return res.sendStatus(500);
        }
        res.setHeader("HX-Redirect", `/items/${req.params.id}`);
        res.sendStatus(200);
      },
    );
  });
});

app.get("/items/:id/edit", (req, res) => {
  db.get("SELECT * FROM Items WHERE id = ?", req.params.id, (err, row) => {
    if (err) {
      console.error("Could not get item", err);
      return res.sendStatus(500);
    }
    res.render("edit-item", {
      title: "Edit Item",
      item: row,
      showImage: false,
      method: "put",
    });
  });
});

app.post("/items/:id/comment", (req, res) => {
  const { content } = req.body;
  if (!content) {
    return res.status(400).send("Content must be supplied");
  }
  db.run(
    `INSERT INTO Comments (item, user, content) VALUES (?, ?, ?)`,
    req.params.id,
    res.locals.userId,
    content,
    (err) => {
      if (err) {
        console.error("Could not create comment", err);
        return res.sendStatus(500);
      }
      res.setHeader("HX-Refresh", "true");
      res.sendStatus(201);
    },
  );
});

app.get("/items/:id/comment/create", (req, res) => {
  res.render("layout", {
    title: "New Comment",
    body: `<form hx-post="/items/${req.params.id}/comment">
      <label for="content">Comment:</label>
      <textarea name="content"></textarea>
      <button type="submit">Add Comment</button>
    </form>`,
  });
});

app.get("/items/:id", (req, res) => {
  db.get(
    `SELECT i.*, l.id as loan_id, u.username
    FROM v_items i 
    LEFT JOIN Loans l ON i.id = l.item 
    LEFT JOIN Users u ON l.user = u.id
    WHERE i.id = ? 
    ORDER BY l.loaned_at DESC;`,
    req.params.id,
    (err, item) => {
      if (err) {
        console.error("Could not fetch item", err);
        return;
      }
      if (!item) {
        res.sendStatus(404);
        return;
      }
      const isOwner = item.owner === res.locals.userId;
      db.all(
        "SELECT * FROM ItemTags WHERE item = ? ORDER BY tag ASC",
        req.params.id,
        (err, tags) => {
          if (err) {
            console.error("Could not get item tags", err);
          }
          db.all(
            'SELECT r.*, u.username FROM Requests r JOIN Users u ON r.user = u.id WHERE item = ? AND status = "pending" ORDER BY created_at DESC',
            item.id,
            (err, requests) => {
              if (err) {
                console.error("Could not fetch requests for item", err);
              }
              const isRequested = requests.some(
                (request) => request.user === res.locals.userId,
              );
              db.all(
                "SELECT c.*, u.username FROM Comments c JOIN Users u ON c.user = u.id WHERE item = ? ORDER BY created_at DESC",
                item.id,
                (err, comments) => {
                  if (err) {
                    console.error("Could not fetch comments", err);
                  }
                  res.render("item", {
                    title: item.name,
                    isOwner,
                    item,
                    tags,
                    requests: requests || [],
                    isRequested,
                    md: marked.parse,
                    comments: comments || [],
                  });
                },
              );
            },
          );
        },
      );
    },
  );
});

app.put("/items/:id/image", upload.single("image"), (req, res) => {
  if (!req.file) {
    return res.status(400).send("File is Required");
  }
  if (req.file) {
    if (
      req.file.mimetype !== "image/jpeg" &&
      req.file.mimetype !== "image/webp"
    ) {
      return res.status(400).send("Image must be either a jpeg or webp");
    }
  }
  db.get(
    "SELECT owner, image FROM Items WHERE id = ?",
    req.params.id,
    (err, row) => {
      if (err) {
        console.error("Could not get item", err);
        return res.sendStatus(500);
      }
      if (row.owner !== res.locals.userId) {
        return res.sendStatus(403);
      }
      const oldImage = row.image;
      db.run(
        "UPDATE Items SET image = ? WHERE id = ?",
        req.file.filename,
        req.params.id,
        (err) => {
          if (err) {
            console.error("Could not set new image", err);
            res.sendStatus(500);
          } else {
            res
              .status(201)
              .send(
                `<img class="item-image" src="/img/${req.file.filename}" />`,
              );
          }
        },
      );
      if (oldImage) {
        fs.unlink(path.join(__dirname, `public/img/${oldImage}`), (err) => {
          if (err) {
            console.error("Error Deleting File", oldImage);
          } else {
            console.log("Successfully deleted file", oldImage);
          }
        });
      }
    },
  );
});

app.get("/items/:id/image/edit", (req, res) => {
  res.send(`<form
      hx-put="/items/${req.params.id}/image"
      enctype="multipart/form-data"
      hx-target=".item-image"
      hx-swap="outerHTML"
    >
      <label for="image">Image (JPEG & WebP only)</label>
      <input type="file" name="image" accept=".jpeg,.jpg,.webp" />
      <button type="Submit">Change Image</button>
    </form>`);
});

app.post("/items/:id/request", (req, res) => {
  let { action } = req.body;
  if (!action) {
    // res
    //   .status(400)
    //   .send("You must specify an action, either Borrow or Consult");
    // return;
    // TODO: Allow multiple actions
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
            res.status(201).send("Requested!");
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

app.post("/items", upload.single("image"), (req, res) => {
  const { name, description } = req.body;
  let image = "";
  if (req.file) {
    if (
      req.file.mimetype !== "image/jpeg" &&
      req.file.mimetype !== "image/webp"
    ) {
      return res.status(400).send("Image must be either a jpeg or webp");
    }
    image = req.file.filename;
  }
  db.run(
    "INSERT INTO Items (name, description, owner, image) VALUES (?, ?, ?, ?)",
    name,
    description,
    res.locals.userId,
    image,
    (err) => {
      if (err) {
        console.error("Failed to add Item", err);
        res.sendStatus(500);
      } else {
        db.get(
          "SELECT id FROM Items WHERE name = ? AND owner = ? ORDER BY id DESC",
          name,
          res.locals.userId,
          (err, row) => {
            if (err) {
              console.error("Could not fetch newly created item", err);
              res.setHeader("HX-Redirect", "/items");
            } else {
              res.setHeader("HX-Redirect", `/items/${row.id}`);
            }
            res.sendStatus(201);
          },
        );
      }
    },
  );
});

app.get("/items/:id/tag", (req, res) => {
  res.render("tag-form", { title: "Tag Item", itemId: req.params.id });
});

app.get("/tags/options", (req, res) => {
  db.all("SELECT * FROM tags ORDER BY tag ASC", (err, rows) => {
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
    "SELECT DISTINCT value FROM ItemTags WHERE tag = ? ORDER BY value ASC",
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

app.delete("/tags/:id", (req, res) => {
  db.run("DELETE FROM ItemTags WHERE id = ?", req.params.id, (err) => {
		if (err) {
			console.error('Could not delete tag', err);
			return res.sendStatus(500);
		}
		res.status(200).send('');
	});
});

app.get("/maximised/:filename", (req, res) => {
  const { filename } = req.params;
  res.render("maximised", { title: "Maximised Image", filename });
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
    db.all(
      "SELECT * FROM v_items WHERE owner = ?",
      res.locals.userId,
      (err, rows) => {
        if (err) {
          console.error("Could not get items", err);
          return res.sendStatus(500);
        }
        res.render("profile", {
          title: "Profile",
          username: row.username,
          items: rows,
        });
      },
    );
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

app.listen(process.env.PORT, () => {
  console.log(`App listening on port ${process.env.PORT}`);
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
