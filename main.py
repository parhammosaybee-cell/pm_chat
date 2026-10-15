import os
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# Set JWT_SECRET_KEY in your terminal before starting the app.
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        'Set JWT_SECRET_KEY first. PowerShell: '
        '$env:JWT_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"'
    )

DATABASE = "chat.db"
TOKEN_MINUTES = 60 * 12
hasher = PasswordHasher()
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Sabz Chat")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
bearer = HTTPBearer(auto_error=False)


def db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
        if "recipient_id" not in cols:
            conn.execute("ALTER TABLE messages ADD COLUMN recipient_id INTEGER")
        if "kind" not in cols:
            conn.execute("ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text'")
        conn.execute("""CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            media_data TEXT NOT NULL,
            media_type TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )""")


init_db()


class RegisterData(BaseModel):
    username: str = Field(min_length=3, max_length=24, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=12, max_length=128)


class LoginData(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=1, max_length=128)


class MessageData(BaseModel):
    body: str = Field(min_length=1, max_length=1000)
    recipient: str = Field(default="", max_length=24)

class VoiceData(BaseModel):
    audio_data: str = Field(min_length=20, max_length=4_500_000)
    recipient: str = Field(min_length=3, max_length=24)
    mime_type: str = Field(default="audio/webm", max_length=80)

class StoryData(BaseModel):
    media_data: str = Field(min_length=20, max_length=7_000_000)
    media_type: str = Field(default="image", pattern="^(image|video)$")


def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if credentials is None:
        raise HTTPException(401, "اول وارد حساب شو")
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=["HS256"],
            options={"require": ["sub", "exp", "iat"]},
        )
        uid = int(payload["sub"])
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(401, "توکن نامعتبر یا منقضی شده است")
    with db() as conn:
        user = conn.execute(
            "SELECT id, username FROM users WHERE id = ?", (uid,)
        ).fetchone()
    if user is None:
        raise HTTPException(401, "حساب پیدا نشد")
    return {"id": user["id"], "username": user["username"]}


@app.get("/", response_class=HTMLResponse)
def home():
    return HTML


@app.post("/api/register", status_code=201)
@limiter.limit("5/minute")
def register(request: Request, data: RegisterData):
    username = data.username.strip()
    password_hash = hasher.hash(data.password)
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                (username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "این نام کاربری قبلاً گرفته شده است")
    return {"id": uid, "username": username, "message": "حساب ساخته شد؛ حالا وارد شو"}


@app.post("/api/login")
@limiter.limit("5/minute")
def login(request: Request, data: LoginData):
    with db() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (data.username.strip(),),
        ).fetchone()
    if user is None:
        raise HTTPException(401, "نام کاربری یا رمز اشتباه است")
    try:
        hasher.verify(user["password_hash"], data.password)
    except (VerifyMismatchError, VerificationError):
        raise HTTPException(401, "نام کاربری یا رمز اشتباه است")
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": str(user["id"]), "iat": now, "exp": now + timedelta(minutes=TOKEN_MINUTES)},
        SECRET_KEY,
        algorithm="HS256",
    )
    return {"access_token": token, "token_type": "bearer", "username": user["username"]}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return user


@app.get("/api/users")
def list_users(q: str = "", user=Depends(current_user)):
    with db() as conn:
        rows = conn.execute("SELECT id, username FROM users WHERE id != ? AND username LIKE ? ORDER BY username LIMIT 100",
                            (user["id"], "%" + q.strip()[:24] + "%")).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/messages")
def list_messages(with_user: str, after: int = 0, user=Depends(current_user)):
    with db() as conn:
        peer = conn.execute("SELECT id, username FROM users WHERE username = ?", (with_user,)).fetchone()
        if peer is None:
            raise HTTPException(404, "کاربر پیدا نشد")
        rows = conn.execute("""
            SELECT m.id, m.body, m.created_at, m.kind, u.username AS sender,
                   CASE WHEN m.user_id = ? THEN 1 ELSE 0 END AS mine
            FROM messages m JOIN users u ON u.id = m.user_id
            WHERE m.id > ? AND (
              (m.user_id = ? AND m.recipient_id = ?) OR
              (m.user_id = ? AND m.recipient_id = ?)
            ) ORDER BY m.id ASC LIMIT 100
        """, (user["id"], max(after, 0), user["id"], peer["id"], peer["id"], user["id"])).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/messages", status_code=201)
@limiter.limit("20/minute")
def send_message(request: Request, data: MessageData, user=Depends(current_user)):
    body = data.body.strip()
    if not body:
        raise HTTPException(400, "پیام خالی است")
    if not data.recipient.strip():
        raise HTTPException(400, "اول یک کاربر انتخاب کن")
    with db() as conn:
        peer = conn.execute("SELECT id FROM users WHERE username = ?", (data.recipient.strip(),)).fetchone()
        if peer is None:
            raise HTTPException(404, "کاربر پیدا نشد")
        if peer["id"] == user["id"]:
            raise HTTPException(400, "نمی‌توانی به خودت پیام بدهی")
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute("INSERT INTO messages(user_id,recipient_id,body,created_at) VALUES(?,?,?,?)",
                           (user["id"], peer["id"], body, now))
        mid = cur.lastrowid
    return {"id": mid, "sender": user["username"], "body": body, "created_at": now, "mine": 1}


@app.get("/api/stories")
def get_stories(user=Depends(current_user)):
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute("DELETE FROM stories WHERE expires_at <= ?", (now,))
        rows = conn.execute("""SELECT s.id, u.username, s.media_data, s.media_type, s.created_at, s.expires_at
            FROM stories s JOIN users u ON u.id=s.user_id ORDER BY s.created_at DESC LIMIT 100""").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/stories", status_code=201)
@limiter.limit("10/hour")
def create_story(request: Request, data: StoryData, user=Depends(current_user)):
    if not data.media_data.startswith(("data:image/", "data:video/")):
        raise HTTPException(400, "فقط عکس یا ویدئو مجاز است")
    if data.media_type == "image" and not data.media_data.startswith("data:image/"):
        raise HTTPException(400, "نوع فایل باید عکس باشد")
    if data.media_type == "video" and not data.media_data.startswith("data:video/"):
        raise HTTPException(400, "نوع فایل باید ویدئو باشد")
    now = datetime.now(timezone.utc)
    with db() as conn:
        cur = conn.execute("INSERT INTO stories(user_id,media_data,media_type,created_at,expires_at) VALUES(?,?,?,?,?)",
            (user["id"], data.media_data, data.media_type, now.isoformat(), (now+timedelta(hours=24)).isoformat()))
    return {"id": cur.lastrowid, "username": user["username"], "expires_at": (now+timedelta(hours=24)).isoformat()}

@app.delete("/api/stories/{story_id}")
def delete_story(story_id: int, user=Depends(current_user)):
    with db() as conn:
        cur = conn.execute("DELETE FROM stories WHERE id=? AND user_id=?", (story_id, user["id"]))
    if not cur.rowcount:
        raise HTTPException(404, "استوری پیدا نشد")
    return {"ok": True}

@app.post("/api/voice", status_code=201)
@limiter.limit("10/minute")
def send_voice(request: Request, data: VoiceData, user=Depends(current_user)):
    if not data.audio_data.startswith("data:audio/"):
        raise HTTPException(400, "فایل صوتی معتبر نیست")
    with db() as conn:
        peer = conn.execute("SELECT id FROM users WHERE username=?", (data.recipient.strip(),)).fetchone()
        if not peer or peer["id"] == user["id"]:
            raise HTTPException(404, "کاربر مقصد پیدا نشد")
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute("INSERT INTO messages(user_id,recipient_id,body,created_at,kind) VALUES(?,?,?,?,?)",
            (user["id"], peer["id"], data.audio_data, now, "voice"))
        mid = cur.lastrowid
    return {"id": mid, "sender": user["username"], "body": data.audio_data, "created_at": now, "mine": 1, "kind": "voice"}


HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PM Chat</title>
<style>
:root{--bg:#090a0e;--panel:#171824;--panel2:#202132;--green:#13c98b;--muted:#9295a9;--line:#292b3a;--white:#f6f7fb}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 50% 10%,#10271f 0,#090a0e 48%);color:var(--white);font-family:Inter,system-ui,-apple-system,"Segoe UI",Arial,sans-serif;min-height:100vh}button,input,select{font:inherit}button{cursor:pointer}.hidden{display:none!important}.shell{width:min(1240px,100%);height:min(850px,100vh);min-height:590px;margin:auto;padding:16px;display:grid;grid-template-columns:310px minmax(0,1fr);gap:14px}.panel{background:rgba(22,23,35,.97);border:1px solid #2c2e3c;border-radius:22px;overflow:hidden;box-shadow:0 20px 65px #0007}.sidebar{display:flex;flex-direction:column;min-width:0}.brand{display:flex;align-items:center;gap:12px;padding:22px 20px;border-bottom:1px solid var(--line)}.logo{width:44px;height:44px;border-radius:15px;background:var(--green);display:grid;place-items:center;color:#06160f;font-size:18px;font-weight:900;box-shadow:0 0 28px #13c98b33}.brand-name{font-size:20px;font-weight:800}.brand-sub{font-size:12px;color:var(--muted);margin-top:3px}.userline{display:flex;align-items:center;gap:11px;padding:16px 18px}.avatar{width:39px;height:39px;flex:0 0 39px;border-radius:50%;background:linear-gradient(135deg,#13c98b,#276b95);display:grid;place-items:center;color:white;font-weight:800}.usertext{min-width:0;flex:1}.usertext strong{display:block;overflow:hidden;text-overflow:ellipsis}.usertext small{color:var(--muted);font-size:12px}.iconbtn{border:1px solid var(--line);background:#202132;color:#e5e6f0;width:38px;height:38px;border-radius:12px}.search{padding:0 16px 14px}.search input,.field{width:100%;border:1px solid #303244;background:#11121c;color:white;border-radius:12px;padding:12px 13px;outline:none}.search input:focus,.field:focus{border-color:var(--green)}.section-label{display:flex;align-items:center;justify-content:space-between;padding:6px 18px 10px;color:var(--muted);font-size:11px;letter-spacing:1.2px;text-transform:uppercase}.people{overflow:auto;padding:0 8px 10px}.person{display:flex;align-items:center;gap:10px;width:100%;text-align:left;border:1px solid transparent;background:transparent;color:inherit;border-radius:14px;padding:10px}.person:hover,.person.active{background:#232536;border-color:#34364a}.person-info{min-width:0;flex:1}.person-info strong{display:block;font-size:13px;overflow:hidden;text-overflow:ellipsis}.person-info small{display:block;color:var(--muted);font-size:11px;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.online-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 10px #13c98b88}.sidebottom{margin-top:auto;border-top:1px solid var(--line);padding:13px 16px;display:flex;gap:8px}.sidebottom button{flex:1}.main{display:flex;flex-direction:column;min-width:0}.topbar{display:flex;align-items:center;gap:12px;padding:17px 20px;border-bottom:1px solid var(--line)}.peer{display:flex;align-items:center;gap:12px;min-width:0;flex:1}.peer h2{font-size:16px;margin:0 0 4px}.peer p{font-size:12px;color:var(--muted);margin:0}.messages{flex:1;overflow:auto;padding:24px;display:flex;flex-direction:column;gap:17px}.welcome{margin:auto;max-width:400px;text-align:center;color:var(--muted);line-height:1.9}.biglogo{margin:0 auto 18px;width:70px;height:70px;border-radius:24px;background:#12372a;border:1px solid #1b7755;color:var(--green);display:grid;place-items:center;font-size:30px}.msgrow{display:flex;align-items:flex-end;gap:9px;max-width:84%}.msgrow.mine{align-self:flex-end;flex-direction:row-reverse}.msgrow .avatar{width:30px;height:30px;flex-basis:30px;font-size:11px}.bubble{background:#232435;border:1px solid #303244;padding:12px 15px;border-radius:17px 17px 17px 5px;overflow-wrap:anywhere;min-width:60px}.mine .bubble{background:linear-gradient(135deg,#0d9c6b,#0e805d);border-color:#1acb91;border-radius:17px 17px 5px 17px}.msgname{font-size:11px;color:#74e6bc;margin-bottom:6px}.msgbody{white-space:pre-wrap;line-height:1.65;font-size:14px}.msgtime{font-size:10px;color:#c0c3d0;margin-top:6px;text-align:right}.composer-wrap{border-top:1px solid var(--line);padding:15px 18px 18px}.composer{display:flex;align-items:center;gap:10px;background:#11121c;border:1px solid #303244;border-radius:17px;padding:7px}.composer input{flex:1;min-width:0;background:transparent;border:0;outline:0;color:white;padding:10px}.send{width:44px;height:44px;border-radius:14px;background:var(--green);color:#06160f;border:0;font-size:20px;font-weight:900}.hint{font-size:11px;color:var(--muted);text-align:center;margin-top:9px}.authscreen{min-height:100vh;display:grid;place-items:center;padding:20px}.authcard{width:min(100%,440px);padding:30px;background:#171824f5;border:1px solid #303244;border-radius:25px;box-shadow:0 25px 90px #0009}.authcard .brand{padding:0;border:0;margin-bottom:28px}.authcard h1{font-size:25px;margin:0 0 8px}.muted{color:var(--muted);font-size:13px;line-height:1.8;margin:0 0 22px}.authform{display:grid;gap:12px}.primary{background:var(--green);border:0;color:#04150d;font-weight:800;border-radius:12px;padding:13px}.secondary{background:#222433;color:#e7e8f1;border:1px solid #353749;border-radius:12px;padding:11px}.switch{display:flex;gap:9px;margin-top:12px}.switch button{flex:1}.error{color:#ff9da7;font-size:12px;min-height:20px;margin-top:10px}.langrow{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:18px;color:var(--muted);font-size:12px}.langrow select,.settings-pop select{background:#11121c;border:1px solid #303244;color:white;border-radius:10px;padding:9px;max-width:190px}.settings{position:relative}.settings-pop{position:absolute;right:0;top:45px;z-index:10;background:#202132;border:1px solid #3a3c50;padding:12px;border-radius:14px;box-shadow:0 15px 40px #0008;min-width:190px}.settings-pop label{display:block;color:var(--muted);font-size:12px;margin-bottom:7px}.settings-pop select{width:100%;max-width:none}.notice{font-size:12px;color:#ffb4b4;min-height:17px;padding:0 5px}.storybar{display:flex;gap:12px;overflow-x:auto;padding:12px 16px;border-bottom:1px solid var(--line)}.storyitem{flex:0 0 70px;border:0;background:transparent;color:white;text-align:center;font-size:11px;overflow:hidden}.storyring{width:58px;height:58px;padding:3px;border-radius:50%;border:2px solid var(--green);margin:0 auto 5px;background:#171824;display:grid;place-items:center}.storyring span{width:100%;height:100%;border-radius:50%;display:grid;place-items:center;background:#25332f;font-weight:800}.storyadd{position:relative}.storyadd input{display:none}.storyviewer{position:fixed;inset:0;background:#050607ee;z-index:99;display:grid;place-items:center;padding:20px}.storyviewer .storycard{max-width:min(92vw,500px);max-height:85vh;position:relative}.storyviewer img,.storyviewer video{max-width:100%;max-height:75vh;border-radius:18px}.storyviewer button{display:block;margin:12px auto}.voicebtn{border:1px solid #285844;background:#132c23;color:#74e6bc;border-radius:12px;padding:0 12px;min-width:44px}.bubble audio{width:min(260px,65vw);display:block}.storybar{min-height:82px}
@media(max-width:760px){.shell{padding:0;height:100dvh;min-height:0;grid-template-columns:1fr;gap:0}.panel{border-radius:0;border-left:0;border-right:0}.sidebar{display:none}.main{height:100dvh}.topbar{padding:13px}.messages{padding:15px}.msgrow{max-width:94%}.composer-wrap{padding:10px}.authscreen{padding:13px}.authcard{padding:23px}}
</style></head><body>
<section class="authscreen" id="auth"><div class="authcard"><div class="brand"><div class="logo">PM</div><div><div class="brand-name">PM Chat</div><div class="brand-sub" data-k="tagline">Your space. Your conversations.</div></div></div><h1 id="authTitle">Welcome back</h1><p class="muted" id="authSub">Sign in or create an account to start chatting privately.</p><form class="authform" id="authForm"><input class="field" id="username" placeholder="Username (letters, numbers, _)" minlength="3" maxlength="24" autocomplete="username" required><input class="field" id="password" type="password" placeholder="Password (12+ characters to sign up)" autocomplete="current-password" required><button class="primary" id="authSubmit">Sign in</button></form><div class="switch"><button class="secondary" id="showLogin" type="button">Sign in</button><button class="secondary" id="showRegister" type="button">Create account</button></div><div class="error" id="authError"></div><div class="langrow"><span data-k="language">Menu language</span><select id="langAuth"></select></div></div></section>
<section class="shell hidden" id="app"><aside class="panel sidebar"><div class="brand"><div class="logo">PM</div><div><div class="brand-name">PM Chat</div><div class="brand-sub" data-k="private">Private messaging</div></div></div><div class="userline"><div class="avatar" id="myAvatar">P</div><div class="usertext"><strong id="myName"></strong><small data-k="online">● Online</small></div><button class="iconbtn" id="logout" title="Sign out">↪</button></div><div class="search"><input id="search" placeholder="Search people..." autocomplete="off"></div><div class="section-label"><span data-k="people">Chats & people</span><span id="peopleCount">0</span></div><div class="people" id="people"></div><div class="sidebottom"><button class="secondary" id="settingsBtn">⚙ <span data-k="settings">Settings</span></button><button class="secondary" id="sideLogout" data-k="logout">Sign out</button></div></aside><main class="panel main"><header class="topbar"><div class="peer"><div class="avatar" id="peerAvatar">PM</div><div><h2 id="peerName">Choose a chat</h2><p id="peerStatus">Select someone to start a private conversation</p></div></div><div class="settings"><button class="iconbtn" id="settingsTop">⋯</button><div class="settings-pop hidden" id="settingsPop"><label data-k="language">Menu language</label><select id="langTop"></select><button class="secondary" id="logoutTop" style="width:100%;margin-top:10px" data-k="logout">Sign out</button></div></div></header><div class="storybar" id="storybar"><button class="storyitem storyadd" id="addStory"><div class="storyring"><span>＋</span></div>استوری من</button><input type="file" id="storyFile" accept="image/*,video/*"></div><div class="messages" id="messages"><div class="welcome" id="welcome"><div class="biglogo">✦</div><strong data-k="welcome">Welcome to PM Chat</strong><br><span data-k="welcomeText">Choose a person to send your first private message.</span></div></div><div class="composer-wrap"><form class="composer" id="sendForm"><button type="button" class="iconbtn" id="emojiBtn">☺</button><input id="message" maxlength="1000" placeholder="Write a message..." autocomplete="off" disabled><button type="button" class="voicebtn" id="voiceBtn" title="ضبط ویس" disabled>🎙</button><button class="send" id="sendBtn" disabled>➤</button></form><div class="notice" id="notice"></div><div class="hint" data-k="hint">Messages are not automatically translated.</div></div></main></section>
<div class="storyviewer hidden" id="storyViewer"><div class="storycard" id="storyCard"></div></div><script>
const L={en:{name:"English",tagline:"Your space. Your conversations.",title:"Welcome back",sub:"Sign in or create an account to start chatting privately.",login:"Sign in",register:"Create account",user:"Username (letters, numbers, _)",pass:"Password (12+ characters to sign up)",language:"Menu language",private:"Private messaging",online:"● Online",people:"Chats & people",settings:"Settings",logout:"Sign out",choose:"Choose a chat",select:"Select someone to start a private conversation",welcome:"Welcome to PM Chat",welcomeText:"Choose a person to send your first private message.",search:"Search people...",write:"Write a message...",hint:"Messages are sent as written and are not automatically translated.",none:"No other users yet. Share the PM Chat link with a friend.",empty:"No users found.",start:"Start the conversation"},fa:{name:"فارسی",tagline:"فضای تو، گفت‌وگوهای تو",title:"خوش برگشتی",sub:"برای گفت‌وگوی خصوصی وارد شو یا حساب بساز.",login:"ورود",register:"ساخت حساب",user:"نام کاربری انگلیسی",pass:"رمز عبور (ثبت‌نام: حداقل ۱۲ حرف)",language:"زبان منو",private:"پیام‌رسان خصوصی",online:"● آنلاین",people:"گفت‌وگوها و کاربران",settings:"تنظیمات",logout:"خروج",choose:"یک گفت‌وگو انتخاب کن",select:"برای گفت‌وگوی خصوصی یک نفر را انتخاب کن",welcome:"به PM Chat خوش آمدی",welcomeText:"برای پیام خصوصی یک نفر را انتخاب کن.",search:"جست‌وجوی کاربران...",write:"پیامت را بنویس...",hint:"پیام‌ها خودکار ترجمه نمی‌شوند.",none:"هنوز کاربر دیگری نیست؛ لینک را برای دوستت بفرست.",empty:"کاربری پیدا نشد.",start:"گفت‌وگو را شروع کن"},tr:{name:"Türkçe",tagline:"Senin alanın, senin sohbetlerin",title:"Tekrar hoş geldin",sub:"Özel sohbet için giriş yap veya hesap oluştur.",login:"Giriş yap",register:"Hesap oluştur",user:"Kullanıcı adı",pass:"Şifre (12+ karakter)",language:"Menü dili",private:"Özel mesajlaşma",online:"● Çevrimiçi",people:"Sohbetler ve kişiler",settings:"Ayarlar",logout:"Çıkış",choose:"Bir sohbet seç",select:"Özel sohbet için birini seç",welcome:"PM Chat'e hoş geldin",welcomeText:"Özel mesaj için bir kişi seç.",search:"Kişileri ara...",write:"Mesaj yaz...",hint:"Mesajlar otomatik çevrilmez.",none:"Henüz başka kullanıcı yok.",empty:"Kullanıcı bulunamadı.",start:"Sohbeti başlat"},az:{name:"Azərbaycanca",tagline:"Sənin məkanın, sənin söhbətlərin",title:"Xoş gəldin",sub:"Şəxsi söhbət üçün daxil ol və ya hesab yarat.",login:"Daxil ol",register:"Hesab yarat",user:"İstifadəçi adı",pass:"Şifrə (12+ simvol)",language:"Menyu dili",private:"Şəxsi mesajlar",online:"● Onlayn",people:"Söhbətlər və istifadəçilər",settings:"Parametrlər",logout:"Çıxış",choose:"Söhbət seç",select:"Şəxsi söhbət üçün birini seç",welcome:"PM Chat-a xoş gəlmisən",welcomeText:"Şəxsi mesaj üçün istifadəçi seç.",search:"İstifadəçiləri axtar...",write:"Mesaj yaz...",hint:"Mesajlar avtomatik tərcümə edilmir.",none:"Hələ başqa istifadəçi yoxdur.",empty:"İstifadəçi tapılmadı.",start:"Söhbətə başla"},ru:{name:"Русский",tagline:"Твоё пространство",title:"С возвращением",sub:"Войдите или создайте аккаунт для личного чата.",login:"Войти",register:"Создать аккаунт",user:"Имя пользователя",pass:"Пароль (12+ символов)",language:"Язык меню",private:"Личные сообщения",online:"● В сети",people:"Чаты и пользователи",settings:"Настройки",logout:"Выйти",choose:"Выберите чат",select:"Выберите пользователя",welcome:"Добро пожаловать в PM Chat",welcomeText:"Выберите пользователя для личного сообщения.",search:"Поиск пользователей...",write:"Написать сообщение...",hint:"Сообщения не переводятся автоматически.",none:"Пока нет других пользователей.",empty:"Пользователи не найдены.",start:"Начать переписку"}};
const LANGS={...L,ar:{...L.en,name:"العربية"},fr:{...L.en,name:"Français"},es:{...L.en,name:"Español"},de:{...L.en,name:"Deutsch"},zh:{...L.en,name:"中文"},hi:{...L.en,name:"हिन्दी"},pt:{...L.en,name:"Português"},ja:{...L.en,name:"日本語"},it:{...L.en,name:"Italiano"}};let lang=localStorage.getItem('pmchat_lang')||'en',token=localStorage.getItem('pmchat_token')||'',username=localStorage.getItem('pmchat_user')||'',peer='',lastId=0,busy=false,registering=false,users=[];const $=id=>document.getElementById(id);function t(k){return (LANGS[lang]||L.en)[k]||L.en[k]||k}function fill(sel){$(sel).innerHTML='';Object.entries(LANGS).forEach(([k,v])=>{let o=document.createElement('option');o.value=k;o.textContent=v.name;$(sel).appendChild(o)});$(sel).value=lang}function setLang(v){lang=LANGS[v]?v:'en';localStorage.setItem('pmchat_lang',lang);fill('langAuth');fill('langTop');document.documentElement.lang=lang;document.documentElement.dir=['fa','ar'].includes(lang)?'rtl':'ltr';document.querySelectorAll('[data-k]').forEach(e=>e.textContent=t(e.dataset.k));$('authTitle').textContent=registering?t('register'):t('title');$('authSub').textContent=t('sub');$('authSubmit').textContent=registering?t('register'):t('login');$('showLogin').textContent=t('login');$('showRegister').textContent=t('register');$('username').placeholder=t('user');$('password').placeholder=t('pass');$('search').placeholder=t('search');$('message').placeholder=t('write');if(!peer){$('peerName').textContent=t('choose');$('peerStatus').textContent=t('select')}renderUsers(users)}fill('langAuth');fill('langTop');$('langAuth').onchange=e=>setLang(e.target.value);$('langTop').onchange=e=>setLang(e.target.value);function mode(r){registering=r;$('authTitle').textContent=r?t('register'):t('title');$('authSubmit').textContent=r?t('register'):t('login');$('authError').textContent=''}$('showLogin').onclick=()=>mode(false);$('showRegister').onclick=()=>mode(true);async function api(url,opts={}){opts.headers={...(opts.headers||{}),...(token?{Authorization:'Bearer '+token}:{})};if(opts.body)opts.headers['Content-Type']='application/json';let r=await fetch(url,opts),d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.detail||'Request failed');return d}function initials(n){return(n||'PM').slice(0,2).toUpperCase()}function showChat(){$('auth').classList.add('hidden');$('app').classList.remove('hidden');$('myName').textContent=username;$('myAvatar').textContent=initials(username);loadUsers();loadStories()}function showAuth(){$('app').classList.add('hidden');$('auth').classList.remove('hidden')}function logout(){token='';username='';peer='';lastId=0;localStorage.removeItem('pmchat_token');localStorage.removeItem('pmchat_user');showAuth()}$('logout').onclick=$('sideLogout').onclick=$('logoutTop').onclick=logout;$('authForm').onsubmit=async e=>{e.preventDefault();$('authError').textContent='';$('authSubmit').disabled=true;try{let u=$('username').value.trim(),p=$('password').value;if(registering){await api('/api/register',{method:'POST',body:JSON.stringify({username:u,password:p})});mode(false);$('authError').textContent='حساب ساخته شد؛ حالا وارد شو';$('username').value=u;$('password').value=''}else{let d=await api('/api/login',{method:'POST',body:JSON.stringify({username:u,password:p})});token=d.access_token;username=d.username;localStorage.setItem('pmchat_token',token);localStorage.setItem('pmchat_user',username);showChat()}}catch(err){$('authError').textContent=err.message}finally{$('authSubmit').disabled=false}};function renderUsers(list){users=list;$('people').innerHTML='';$('peopleCount').textContent=list.length;if(!list.length){let e=document.createElement('div');e.className='welcome';e.textContent=$('search').value?t('empty'):t('none');$('people').appendChild(e);return}list.forEach(u=>{let b=document.createElement('button');b.className='person'+(peer===u.username?' active':'');b.onclick=()=>selectPeer(u.username);let av=document.createElement('div');av.className='avatar';av.textContent=initials(u.username);let info=document.createElement('div');info.className='person-info';let n=document.createElement('strong');n.textContent=u.username;let sm=document.createElement('small');sm.textContent=u.username===peer?t('start'):'@'+u.username;info.append(n,sm);let dot=document.createElement('span');dot.className='online-dot';b.append(av,info,dot);$('people').appendChild(b)})}async function loadUsers(){try{renderUsers(await api('/api/users?q='+encodeURIComponent($('search').value)))}catch(e){$('notice').textContent=e.message}}$('search').oninput=loadUsers;async function selectPeer(n){peer=n;lastId=0;$('peerName').textContent=n;$('peerStatus').textContent='@'+n;$('peerAvatar').textContent=initials(n);$('message').disabled=false;$('sendBtn').disabled=false;$('voiceBtn').disabled=false;renderUsers(users);$('messages').innerHTML='';let w=document.createElement('div');w.className='welcome';w.textContent=t('start');w.id='welcome';$('messages').appendChild(w);await loadMessages(true)}function addMessage(m){let w=$('welcome');if(w)w.remove();let row=document.createElement('div');row.className='msgrow'+(m.mine?' mine':'');let av=document.createElement('div');av.className='avatar';av.textContent=initials(m.sender);let b=document.createElement('div');b.className='bubble';if(!m.mine){let n=document.createElement('div');n.className='msgname';n.textContent=m.sender;b.appendChild(n)}let body=document.createElement('div');body.className='msgbody';if(m.kind==='voice'){let audio=document.createElement('audio');audio.controls=true;audio.src=m.body;body.appendChild(audio)}else{body.textContent=m.body}let time=document.createElement('div');time.className='msgtime';try{time.textContent=new Date(m.created_at).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}catch{}b.append(body,time);row.append(av,b);$('messages').appendChild(row);$('messages').scrollTop=$('messages').scrollHeight;lastId=Math.max(lastId,m.id)}async function loadMessages(initial=false){if(!token||!peer||busy)return;busy=true;try{let list=await api('/api/messages?with_user='+encodeURIComponent(peer)+'&after='+(initial?0:lastId));if(initial){$('messages').innerHTML='';lastId=0;if(!list.length){let w=document.createElement('div');w.className='welcome';w.id='welcome';w.textContent=t('start');$('messages').appendChild(w)}}list.forEach(addMessage);$('notice').textContent=''}catch(e){$('notice').textContent=e.message}finally{busy=false}}$('sendForm').onsubmit=async e=>{e.preventDefault();let body=$('message').value.trim();if(!body||!peer)return;$('sendBtn').disabled=true;try{let m=await api('/api/messages',{method:'POST',body:JSON.stringify({body,recipient:peer})});$('message').value='';addMessage(m)}catch(err){$('notice').textContent=err.message}finally{$('sendBtn').disabled=false;$('message').focus()}};$('emojiBtn').onclick=()=>{$('message').value+=' 😊';$('message').focus()};
async function loadStories(){if(!token)return;try{const list=await api('/api/stories');const bar=$('storybar');bar.querySelectorAll('.storyitem:not(.storyadd)').forEach(x=>x.remove());list.forEach(s=>{const b=document.createElement('button');b.className='storyitem';b.onclick=()=>viewStory(s);const ring=document.createElement('div');ring.className='storyring';const sp=document.createElement('span');sp.textContent=initials(s.username);ring.append(sp);const name=document.createElement('div');name.textContent=s.username;b.append(ring,name);bar.appendChild(b)})}catch(e){}}
function viewStory(s){const card=$('storyCard');card.innerHTML='';const title=document.createElement('div');title.style.cssText='text-align:center;color:white;margin-bottom:12px';title.textContent=s.username+' · استوری ۲۴ ساعته';let media;if(s.media_type==='video'){media=document.createElement('video');media.controls=true;media.autoplay=true}else{media=document.createElement('img')}media.src=s.media_data;card.append(title,media);if(s.username===username){const del=document.createElement('button');del.className='secondary';del.textContent='حذف استوری';del.onclick=async()=>{try{await api('/api/stories/'+s.id,{method:'DELETE'});$('storyViewer').classList.add('hidden');loadStories()}catch(e){$('notice').textContent=e.message}};card.appendChild(del)}const close=document.createElement('button');close.className='secondary';close.textContent='بستن';close.onclick=()=>$('storyViewer').classList.add('hidden');card.appendChild(close);$('storyViewer').classList.remove('hidden')}
$('storyViewer').onclick=e=>{if(e.target===$('storyViewer'))$('storyViewer').classList.add('hidden')};$('addStory').onclick=()=>{if(!token)return;$('storyFile').click()};$('storyFile').onchange=async e=>{const f=e.target.files[0];if(!f)return;if(f.size>5*1024*1024){$('notice').textContent='حجم استوری باید کمتر از ۵ مگابایت باشد';e.target.value='';return}const type=f.type.startsWith('video/')?'video':'image';const reader=new FileReader();reader.onload=async()=>{try{await api('/api/stories',{method:'POST',body:JSON.stringify({media_data:reader.result,media_type:type})});await loadStories();$('notice').textContent='استوری تا ۲۴ ساعت نمایش داده می‌شود'}catch(err){$('notice').textContent=err.message}};reader.readAsDataURL(f);e.target.value=''};
let recorder=null,chunks=[];async function toggleVoice(){if(!peer){$('notice').textContent='اول یک گفت‌وگو انتخاب کن';return}if(recorder&&recorder.state==='recording'){recorder.stop();$('voiceBtn').textContent='🎙';return}try{const stream=await navigator.mediaDevices.getUserMedia({audio:true});recorder=new MediaRecorder(stream);chunks=[];recorder.ondataavailable=e=>{if(e.data.size)chunks.push(e.data)};recorder.onstop=async()=>{stream.getTracks().forEach(t=>t.stop());const blob=new Blob(chunks,{type:recorder.mimeType||'audio/webm'});if(blob.size>3*1024*1024){$('notice').textContent='ویس طولانی است؛ کوتاه‌تر ضبط کن';return}const reader=new FileReader();reader.onload=async()=>{try{const m=await api('/api/voice',{method:'POST',body:JSON.stringify({audio_data:reader.result,recipient:peer,mime_type:blob.type})});addMessage(m)}catch(err){$('notice').textContent=err.message}};reader.readAsDataURL(blob)};recorder.start();$('voiceBtn').textContent='⏹';$('notice').textContent='در حال ضبط؛ برای پایان دوباره روی دکمه بزن'}catch(e){$('notice').textContent='برای ضبط ویس اجازهٔ میکروفون بده؛ سایت باید HTTPS باشد'}}$('voiceBtn').onclick=toggleVoice;
$('settingsTop').onclick=()=>$('settingsPop').classList.toggle('hidden');$('settingsBtn').onclick=()=>$('settingsPop').classList.toggle('hidden');if(token&&username)showChat();else showAuth();setLang(lang);setInterval(()=>{if(token&&!$('app').classList.contains('hidden')){loadUsers();loadStories();if(peer)loadMessages(false)}},3000);
</script></body></html>"""
