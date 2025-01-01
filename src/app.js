const sqlite3 = require("sqlite3");
const db = new sqlite3.Database("./database.db");

db.serialize(() => {
	db.run(`CREATE TABLE IF NOT EXISTS Items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		format TEXT,
		owner INTEGER,
		accessibility INTEGER,
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
});

db.close();
