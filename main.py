import sqlite3
import random, string
from flask import Flask, make_response, request, redirect, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import markdown
import bleach
from waitress import serve

# DB初期化
def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'user'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session TEXT UNIQUE,
            username TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS wikis (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            code TEXT UNIQUE,
            title TEXT,
            text TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# Flask
app = Flask(__name__, static_folder="static", template_folder="templates")

def generate_code(length=32):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))

def get_login_user():
    session = request.cookies.get("session")
    if not session:
        return None

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("""
        SELECT users.username, users.role
        FROM sessions
        JOIN users ON sessions.username = users.username
        WHERE sessions.session=?
    """, (session,))
    user = cur.fetchone()
    conn.close()
    return user  # (username, role)

def require_admin():
    user = get_login_user()
    return user is not None and user[1] == "admin"

# ルート
@app.get("/")
def index():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("""
        SELECT code, title, username
        FROM wikis
        ORDER BY id DESC
    """)
    pages = cur.fetchall()
    conn.close()

    user = get_login_user()

    return render_template(
        "index.html",
        pages=pages,
        is_admin=(user and user[1] == "admin")
    )

@app.get("/wiki/<code>")
def wiki_view(code):
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("""
        SELECT title, text, username
        FROM wikis
        WHERE code=?
    """, (code,))
    page = cur.fetchone()
    conn.close()

    if not page:
        return "ページが見つかりません"

    html = markdown.markdown(
        page[1],
        extensions=[
            "fenced_code",
            "tables",
            "codehilite"  # ← 追加（任意）
        ]
    )

    allowed_tags = set(bleach.sanitizer.ALLOWED_TAGS)

    allowed_tags.update([
        "p", "pre", "code",
        "h1", "h2", "h3",
        "table", "tr", "td", "th",
        "blockquote", "ul", "ol", "li",
        "strong", "em", "hr", "br",
        "a", "img", "thead", "tbody",
    ])

    allowed_attrs = {
        "a": ["href", "title"],
        "img": ["src", "alt", "title"]
    }

    html = bleach.clean(
        html,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )

    user = get_login_user()

    return render_template(
        "wiki.html",
        title=page[0],
        html=html,
        author=page[2],
        code=code,
        is_admin=(user and user[1] == "admin")
    )

# ログイン / ログアウト
@app.get("/login")
def login():
    return render_template("login.html")

@app.post("/login/callback")
def login_callback():
    username = request.form["name"]
    password = request.form["password"]

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute(
        "SELECT username, password FROM users WHERE username=?",
        (username,)
    )
    user = cur.fetchone()
    conn.close()

    if not user or not check_password_hash(user[1], password):
        return "ユーザー名またはパスワードが違います"

    session_code = generate_code()

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO sessions (session, username) VALUES (?, ?)",
        (session_code, user[0])
    )
    conn.commit()
    conn.close()

    response = make_response(redirect("/admin/wiki/create"))
    response.set_cookie(
        "session",
        session_code,
        max_age=3600,
        httponly=True,
        samesite="Lax"
    )
    return response

@app.get("/logout")
def logout():
    response = make_response(redirect("/"))
    response.delete_cookie("session")
    return response

# 管理画面
@app.get("/admin/wiki/create")
def admin_wiki_create():
    if not require_admin():
        return "権限がありません"

    return render_template("wiki_create.html")

@app.post("/admin/wiki/create")
def admin_wiki_create_post():
    if not require_admin():
        return "権限がありません"

    title = request.form["title"]
    text = request.form["text"]
    code = generate_code(12)

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO wikis (username, code, title, text)
        VALUES (?, ?, ?, ?)
    """, (get_login_user()[0], code, title, text))
    conn.commit()
    conn.close()

    return redirect(f"/wiki/{code}")

@app.get("/admin/wiki/edit/<code>")
def admin_wiki_edit(code):
    if not require_admin():
        return "権限がありません"

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("""
        SELECT title, text
        FROM wikis
        WHERE code=?
    """, (code,))
    page = cur.fetchone()
    conn.close()

    if not page:
        return "ページが存在しません"

    return render_template(
        "wiki_edit.html",
        code=code,
        title=page[0],
        text=page[1]
    )

@app.post("/admin/wiki/edit/<code>")
def admin_wiki_edit_post(code):
    if not require_admin():
        return "権限がありません"

    title = request.form["title"]
    text = request.form["text"]

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("""
        UPDATE wikis
        SET title=?, text=?
        WHERE code=?
    """, (title, text, code))
    conn.commit()
    conn.close()

    return redirect(f"/wiki/{code}")

@app.post("/admin/wiki/delete/<code>")
def admin_wiki_delete(code):
    if not require_admin():
        return "権限がありません"

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM wikis WHERE code=?", (code,))
    conn.commit()
    conn.close()

    return redirect("/")

# 起動
if __name__ == "__main__":
    # app.run("0.0.0.0", port=5008, debug=True)
    serve(app, host='0.0.0.0', port=5009)