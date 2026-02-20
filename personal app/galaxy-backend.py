from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
import sqlite3, hashlib, os, functools

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = "galaxy-secret-key-change-this"
CORS(app, supports_credentials=True)
DB = "galaxy.db"

# ── Database ────────────────────────────────────────────────────
def get_db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    c = get_db()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS expenses (
            id TEXT PRIMARY KEY, user_id INTEGER,
            amount REAL, category TEXT, note TEXT, date TEXT
        );
        CREATE TABLE IF NOT EXISTS todos (
            id TEXT PRIMARY KEY, user_id INTEGER,
            text TEXT, done INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS habits (
            id TEXT PRIMARY KEY, user_id INTEGER, name TEXT
        );
        CREATE TABLE IF NOT EXISTS habit_logs (
            habit_id TEXT, user_id INTEGER, date TEXT,
            UNIQUE(habit_id, user_id, date)
        );
        CREATE TABLE IF NOT EXISTS reflections (
            user_id INTEGER, date TEXT, rating INTEGER, note TEXT,
            UNIQUE(user_id, date)
        );
        CREATE TABLE IF NOT EXISTS reminders (
            id TEXT PRIMARY KEY, user_id INTEGER,
            title TEXT, datetime TEXT, fired INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS goals (
            id TEXT PRIMARY KEY, user_id INTEGER,
            title TEXT, target_date TEXT,
            progress INTEGER DEFAULT 0, done INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS calendar_events (
            user_id INTEGER, date TEXT, note TEXT, occasion TEXT,
            UNIQUE(user_id, date)
        );
    """)
    c.commit()
    c.close()

def hash_pw(p):
    return hashlib.sha256(p.encode()).hexdigest()

def auth(f):
    @functools.wraps(f)
    def wrap(*a, **kw):
        if "uid" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*a, **kw)
    return wrap

# ── Auth ────────────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    d = request.json
    u = d.get("username", "").strip().lower()
    p = d.get("password", "")
    dn = d.get("displayName", u)
    if len(u) < 3: return jsonify({"error": "Username must be 3+ characters"}), 400
    if len(p) < 4: return jsonify({"error": "Password must be 4+ characters"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users (username,password_hash,display_name) VALUES (?,?,?)", (u, hash_pw(p), dn))
        db.commit()
        row = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        session["uid"] = row["id"]; session["dn"] = dn
        return jsonify({"success": True, "displayName": dn})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already taken"}), 400
    finally:
        db.close()

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json
    u = d.get("username", "").strip().lower()
    p = d.get("password", "")
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=? AND password_hash=?", (u, hash_pw(p))).fetchone()
    db.close()
    if not row: return jsonify({"error": "Wrong username or password"}), 401
    session["uid"] = row["id"]; session["dn"] = row["display_name"]
    return jsonify({"success": True, "displayName": row["display_name"]})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/me")
def me():
    if "uid" not in session: return jsonify({"loggedIn": False})
    return jsonify({"loggedIn": True, "displayName": session["dn"]})

# ── Expenses ────────────────────────────────────────────────────
@app.route("/api/expenses", methods=["GET","POST"])
@auth
def expenses():
    uid = session["uid"]; db = get_db()
    if request.method == "POST":
        d = request.json
        db.execute("INSERT INTO expenses (id,user_id,amount,category,note,date) VALUES (?,?,?,?,?,?)",
            (d["id"], uid, d["amount"], d["category"], d.get("note",""), d["date"]))
        db.commit(); db.close(); return jsonify({"success": True})
    rows = db.execute("SELECT * FROM expenses WHERE user_id=? ORDER BY date DESC", (uid,)).fetchall()
    db.close(); return jsonify([dict(r) for r in rows])

@app.route("/api/expenses/<id>", methods=["DELETE"])
@auth
def del_expense(id):
    db = get_db()
    db.execute("DELETE FROM expenses WHERE id=? AND user_id=?", (id, session["uid"]))
    db.commit(); db.close(); return jsonify({"success": True})

# ── Todos ───────────────────────────────────────────────────────
@app.route("/api/todos", methods=["GET","POST"])
@auth
def todos():
    uid = session["uid"]; db = get_db()
    if request.method == "POST":
        d = request.json
        db.execute("INSERT INTO todos (id,user_id,text,done) VALUES (?,?,?,0)", (d["id"], uid, d["text"]))
        db.commit(); db.close(); return jsonify({"success": True})
    rows = db.execute("SELECT * FROM todos WHERE user_id=? ORDER BY created_at DESC", (uid,)).fetchall()
    db.close(); return jsonify([dict(r) for r in rows])

@app.route("/api/todos/<id>", methods=["PUT","DELETE"])
@auth
def todo_item(id):
    db = get_db()
    if request.method == "DELETE":
        db.execute("DELETE FROM todos WHERE id=? AND user_id=?", (id, session["uid"]))
    else:
        db.execute("UPDATE todos SET done=? WHERE id=? AND user_id=?", (request.json["done"], id, session["uid"]))
    db.commit(); db.close(); return jsonify({"success": True})

# ── Habits ──────────────────────────────────────────────────────
@app.route("/api/habits", methods=["GET","POST"])
@auth
def habits():
    uid = session["uid"]; db = get_db()
    if request.method == "POST":
        d = request.json
        db.execute("INSERT INTO habits (id,user_id,name) VALUES (?,?,?)", (d["id"], uid, d["name"]))
        db.commit(); db.close(); return jsonify({"success": True})
    rows = db.execute("SELECT * FROM habits WHERE user_id=?", (uid,)).fetchall()
    db.close(); return jsonify([dict(r) for r in rows])

@app.route("/api/habits/<id>", methods=["DELETE"])
@auth
def del_habit(id):
    db = get_db()
    db.execute("DELETE FROM habits WHERE id=? AND user_id=?", (id, session["uid"]))
    db.execute("DELETE FROM habit_logs WHERE habit_id=? AND user_id=?", (id, session["uid"]))
    db.commit(); db.close(); return jsonify({"success": True})

@app.route("/api/habit-logs", methods=["GET","POST"])
@auth
def habit_logs():
    uid = session["uid"]; db = get_db()
    if request.method == "POST":
        d = request.json
        if d["checked"]:
            try: db.execute("INSERT INTO habit_logs (habit_id,user_id,date) VALUES (?,?,?)", (d["habitId"], uid, d["date"]))
            except: pass
        else:
            db.execute("DELETE FROM habit_logs WHERE habit_id=? AND user_id=? AND date=?", (d["habitId"], uid, d["date"]))
        db.commit(); db.close(); return jsonify({"success": True})
    rows = db.execute("SELECT * FROM habit_logs WHERE user_id=?", (uid,)).fetchall()
    db.close(); return jsonify([dict(r) for r in rows])

# ── Reflections ─────────────────────────────────────────────────
@app.route("/api/reflections", methods=["GET","POST"])
@auth
def reflections():
    uid = session["uid"]; db = get_db()
    if request.method == "POST":
        d = request.json
        db.execute("INSERT OR REPLACE INTO reflections (user_id,date,rating,note) VALUES (?,?,?,?)",
            (uid, d["date"], d["rating"], d["note"]))
        db.commit(); db.close(); return jsonify({"success": True})
    rows = db.execute("SELECT * FROM reflections WHERE user_id=? ORDER BY date DESC", (uid,)).fetchall()
    db.close(); return jsonify([dict(r) for r in rows])

# ── Reminders ───────────────────────────────────────────────────
@app.route("/api/reminders", methods=["GET","POST"])
@auth
def reminders():
    uid = session["uid"]; db = get_db()
    if request.method == "POST":
        d = request.json
        db.execute("INSERT INTO reminders (id,user_id,title,datetime) VALUES (?,?,?,?)",
            (d["id"], uid, d["title"], d["datetime"]))
        db.commit(); db.close(); return jsonify({"success": True})
    rows = db.execute("SELECT * FROM reminders WHERE user_id=? ORDER BY datetime ASC", (uid,)).fetchall()
    db.close(); return jsonify([dict(r) for r in rows])

@app.route("/api/reminders/<id>", methods=["DELETE"])
@auth
def del_reminder(id):
    db = get_db()
    db.execute("DELETE FROM reminders WHERE id=? AND user_id=?", (id, session["uid"]))
    db.commit(); db.close(); return jsonify({"success": True})

# ── Goals ───────────────────────────────────────────────────────
@app.route("/api/goals", methods=["GET","POST"])
@auth
def goals():
    uid = session["uid"]; db = get_db()
    if request.method == "POST":
        d = request.json
        db.execute("INSERT INTO goals (id,user_id,title,target_date,progress,done) VALUES (?,?,?,?,?,0)",
            (d["id"], uid, d["title"], d.get("target",""), d.get("progress",0)))
        db.commit(); db.close(); return jsonify({"success": True})
    rows = db.execute("SELECT * FROM goals WHERE user_id=?", (uid,)).fetchall()
    db.close(); return jsonify([dict(r) for r in rows])

@app.route("/api/goals/<id>", methods=["PUT","DELETE"])
@auth
def goal_item(id):
    db = get_db()
    if request.method == "DELETE":
        db.execute("DELETE FROM goals WHERE id=? AND user_id=?", (id, session["uid"]))
    else:
        d = request.json
        if "progress" in d:
            db.execute("UPDATE goals SET progress=? WHERE id=? AND user_id=?", (d["progress"], id, session["uid"]))
        if "done" in d:
            db.execute("UPDATE goals SET done=? WHERE id=? AND user_id=?", (d["done"], id, session["uid"]))
    db.commit(); db.close(); return jsonify({"success": True})

# ── Calendar ────────────────────────────────────────────────────
@app.route("/api/calendar", methods=["GET","POST"])
@auth
def calendar():
    uid = session["uid"]; db = get_db()
    if request.method == "POST":
        d = request.json
        db.execute("INSERT OR REPLACE INTO calendar_events (user_id,date,note,occasion) VALUES (?,?,?,?)",
            (uid, d["date"], d.get("note",""), d.get("occasion","")))
        db.commit(); db.close(); return jsonify({"success": True})
    rows = db.execute("SELECT * FROM calendar_events WHERE user_id=?", (uid,)).fetchall()
    db.close(); return jsonify([dict(r) for r in rows])

@app.route("/api/calendar/<date>", methods=["DELETE"])
@auth
def del_calendar(date):
    db = get_db()
    db.execute("DELETE FROM calendar_events WHERE date=? AND user_id=?", (date, session["uid"]))
    db.commit(); db.close(); return jsonify({"success": True})

# ── Serve Frontend ──────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("templates", "index.html")

if __name__ == "__main__":
    init_db()
    print("🌌 Dashboard running at http://localhost:8080")
    app.run(debug=True,host="0.0.0.0",port=8080)
