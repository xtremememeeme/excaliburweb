"""
Excalibur Tours Georgia — Backend
"""
import os, sqlite3, hashlib, hmac as _hmac, secrets, time, base64, struct, json, io, re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, send_file, g
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)

# SECRET_KEY must be set as an environment variable in production (Render).
# If not set, a random key is generated — this will invalidate sessions on restart.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# DB path: use RENDER_DB_PATH env var if set (point to a Render Persistent Disk),
# otherwise fall back to the project directory (fine for local dev).
DB_PATH = os.environ.get("RENDER_DB_PATH") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "excalibur.db")

# Fernet encryption key: stored as a base64 env var in production.
# Falls back to file-based key for local development.
KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".enc_key")

def get_fernet():
    # Prefer env var (required on Render where filesystem is ephemeral)
    env_key = os.environ.get("FERNET_KEY")
    if env_key:
        return Fernet(env_key.encode() if isinstance(env_key, str) else env_key)
    # Local dev fallback: file-based key
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH,"rb") as f: return Fernet(f.read())
    k = Fernet.generate_key()
    with open(KEY_PATH,"wb") as f: f.write(k)
    return Fernet(k)

fernet = get_fernet()
def encrypt(t): return fernet.encrypt(t.encode()).decode()
def decrypt(t): return fernet.decrypt(t.encode()).decode()

def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()

def totp_code(secret, ts=None):
    if ts is None: ts = int(time.time())
    key = base64.b32decode(secret, casefold=True)
    msg = struct.pack(">Q", ts // 30)
    h   = _hmac.new(key, msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    val = struct.unpack(">I", h[off:off+4])[0] & 0x7FFFFFFF
    return str(val % 1000000).zfill(6)

def totp_verify(secret, code):
    t = int(time.time())
    return any(totp_code(secret, t + d*30) == code.strip() for d in (-1,0,1))

def make_totp_uri(secret, email):
    lbl = f"Excalibur Tours Georgia:{email}"
    return f"otpauth://totp/{lbl}?secret={secret}&issuer=Excalibur%20Tours%20Georgia&algorithm=SHA1&digits=6&period=30"

def make_qr_png(data):
    try:
        import qrcode as qrc
        buf = io.BytesIO(); qrc.make(data).save(buf,"PNG"); return buf.getvalue()
    except ImportError: pass
    from PIL import Image, ImageDraw
    img = Image.new("RGB",(300,300),"white"); draw = ImageDraw.Draw(img)
    draw.rectangle([10,10,290,290],outline="black",width=3)
    draw.text((150,150),"Scan in\nGoogle Auth",fill="black",anchor="mm")
    buf = io.BytesIO(); img.save(buf,"PNG"); return buf.getvalue()

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db",None)
    if db: db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript("""
    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        locked_until REAL DEFAULT 0,
        created_at REAL DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        secret_word_hash TEXT NOT NULL,
        totp_secret TEXT NOT NULL,
        totp_active INTEGER DEFAULT 0,
        failed_attempts INTEGER DEFAULT 0,
        locked_until REAL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS site_lockout (
        id INTEGER PRIMARY KEY DEFAULT 1,
        locked_until REAL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS ip_lockouts (
        ip TEXT PRIMARY KEY,
        locked_until REAL NOT NULL,
        reason TEXT DEFAULT 'admin_failure'
    );
    CREATE TABLE IF NOT EXISTS transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        origin TEXT NOT NULL,
        destination TEXT NOT NULL,
        vehicle_class TEXT NOT NULL,
        max_luggage INTEGER NOT NULL,
        max_passengers INTEGER NOT NULL,
        price_eur REAL NOT NULL,
        created_by INTEGER NOT NULL,
        created_at REAL DEFAULT (strftime('%s','now')),
        updated_at REAL DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        transfer_id INTEGER NOT NULL,
        travel_date TEXT NOT NULL,
        passengers INTEGER NOT NULL,
        luggage INTEGER NOT NULL,
        price_eur REAL NOT NULL,
        status TEXT DEFAULT 'confirmed',
        created_at REAL DEFAULT (strftime('%s','now')),
        FOREIGN KEY(customer_id) REFERENCES customers(id),
        FOREIGN KEY(transfer_id) REFERENCES transfers(id)
    );
    INSERT OR IGNORE INTO site_lockout (id, locked_until) VALUES (1, 0);
    """)
    # Migration: add new columns to bookings if missing
    existing = {row[1] for row in db.execute("PRAGMA table_info(bookings)").fetchall()}
    for col, typedef in [("full_name","TEXT DEFAULT ''"),("phone","TEXT DEFAULT ''"),("flight_number","TEXT DEFAULT ''")]:
        if col not in existing:
            db.execute(f"ALTER TABLE bookings ADD COLUMN {col} {typedef}")
    admins = [
        ("excrebminate@gmail.com",        "20AsD_213DDsxzQ1", "secretwordlol"),
        ("excaliburtoursgeorgia@yahoo.com","SD9A04789324__123","lolwordsecret"),
    ]
    for em, pw, sw in admins:
        if not db.execute("SELECT id FROM admin WHERE email=?",(em,)).fetchone():
            ph  = generate_password_hash(pw, method="pbkdf2:sha256",salt_length=16)
            swh = generate_password_hash(sw, method="pbkdf2:sha256",salt_length=16)
            enc = encrypt(new_totp_secret())
            db.execute(
                "INSERT INTO admin(email,password_hash,secret_word_hash,totp_secret,totp_active) "
                "VALUES(?,?,?,?,0)",(em,ph,swh,enc))
    db.commit(); db.close()

def get_ip():
    fwd = request.headers.get("X-Forwarded-For")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")

def site_lock_until():
    db = get_db()
    r  = db.execute("SELECT locked_until FROM site_lockout WHERE id=1").fetchone()
    return float(r["locked_until"]) if r else 0.0

def set_site_lock(secs):
    db = get_db()
    db.execute("UPDATE site_lockout SET locked_until=? WHERE id=1",(time.time()+secs,))
    db.commit()

def ip_lock_until(ip):
    db = get_db()
    r  = db.execute("SELECT locked_until FROM ip_lockouts WHERE ip=?",(ip,)).fetchone()
    return float(r["locked_until"]) if r else 0.0

def set_ip_lock(ip, secs, reason="admin_failure"):
    db = get_db()
    db.execute(
        "INSERT INTO ip_lockouts(ip,locked_until,reason) VALUES(?,?,?) "
        "ON CONFLICT(ip) DO UPDATE SET locked_until=excluded.locked_until,reason=excluded.reason",
        (ip, time.time()+secs, reason))
    db.commit()

def clear_ip_lock(ip):
    get_db().execute("DELETE FROM ip_lockouts WHERE ip=?",(ip,))
    get_db().commit()

def pw_valid(pw):
    return (len(pw)>=8 and re.search(r"[A-Z]",pw) and re.search(r"[a-z]",pw)
            and re.search(r"\d",pw) and re.search(r"[^A-Za-z0-9]",pw))

def lock_check(f):
    @wraps(f)
    def w(*a,**k):
        ip  = get_ip(); now = time.time()
        st  = site_lock_until(); ipt = ip_lock_until(ip)
        if now < st:  return jsonify({"error":"site_locked","remaining":int(st-now)}),  423
        if now < ipt: return jsonify({"error":"ip_locked",  "remaining":int(ipt-now)}), 423
        return f(*a,**k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a,**k):
        if not session.get("admin_authenticated"):
            return jsonify({"error":"Unauthorized"}),401
        return f(*a,**k)
    return w

# ═══════════════════════ EMAIL ════════════════════════════════════════════════

def send_booking_email(to_email, booking_info):
    """Send booking notification email to a single admin address."""
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 587))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    if not smtp_user or not smtp_pass:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🗡 New Booking — {booking_info['origin']} → {booking_info['destination']} on {booking_info['travel_date']}"
        msg["From"]    = smtp_user
        msg["To"]      = to_email

        plain = (
            f"New booking received!\n\n"
            f"Customer:    {booking_info['customer_name']} ({booking_info['customer_email']})\n"
            f"Phone:       {booking_info.get('phone','—')}\n"
            f"Route:       {booking_info['origin']} → {booking_info['destination']}\n"
            f"Date:        {booking_info['travel_date']}\n"
            f"Vehicle:     {booking_info['vehicle_class']}\n"
            f"Passengers:  {booking_info['passengers']}\n"
            f"Luggage:     {booking_info['luggage']}\n"
            f"Flight No.:  {booking_info.get('flight_number','—') or '—'}\n"
            f"Price:       €{booking_info['price_eur']:.2f}\n"
        )

        html = f"""
<html><body style="font-family:Arial,sans-serif;background:#0a0a0a;color:#e8e8e8;padding:24px">
  <div style="max-width:520px;margin:0 auto;background:#111;border:1px solid #222;border-radius:14px;overflow:hidden">
    <div style="background:linear-gradient(135deg,#7f0000,#E63946);padding:20px 24px">
      <h2 style="margin:0;font-size:1.3rem;letter-spacing:.08em">🗡 New Transfer Booking</h2>
      <p style="margin:4px 0 0;font-size:.85rem;opacity:.8">Excalibur Tours Georgia</p>
    </div>
    <div style="padding:24px">
      <table style="width:100%;border-collapse:collapse;font-size:.95rem">
        <tr><td style="padding:6px 0;color:#888;width:130px">Customer</td><td style="padding:6px 0;font-weight:600">{booking_info['customer_name']}</td></tr>
        <tr><td style="padding:6px 0;color:#888">Email</td><td style="padding:6px 0">{booking_info['customer_email']}</td></tr>
        <tr><td style="padding:6px 0;color:#888">Phone</td><td style="padding:6px 0">{booking_info.get('phone','—') or '—'}</td></tr>
        <tr><td colspan="2" style="padding:8px 0"><hr style="border:none;border-top:1px solid #222"></td></tr>
        <tr><td style="padding:6px 0;color:#888">Route</td><td style="padding:6px 0;font-weight:700;color:#E63946">{booking_info['origin']} → {booking_info['destination']}</td></tr>
        <tr><td style="padding:6px 0;color:#888">Date</td><td style="padding:6px 0;font-weight:700">{booking_info['travel_date']}</td></tr>
        <tr><td style="padding:6px 0;color:#888">Vehicle</td><td style="padding:6px 0">{booking_info['vehicle_class']}</td></tr>
        <tr><td style="padding:6px 0;color:#888">Passengers</td><td style="padding:6px 0">{booking_info['passengers']}</td></tr>
        <tr><td style="padding:6px 0;color:#888">Luggage</td><td style="padding:6px 0">{booking_info['luggage']}</td></tr>
        <tr><td style="padding:6px 0;color:#888">Flight No.</td><td style="padding:6px 0">{booking_info.get('flight_number','—') or '—'}</td></tr>
        <tr><td colspan="2" style="padding:8px 0"><hr style="border:none;border-top:1px solid #222"></td></tr>
        <tr><td style="padding:6px 0;color:#888">Price</td><td style="padding:6px 0;font-size:1.2rem;font-weight:700;color:#4CAF50">€{booking_info['price_eur']:.2f}</td></tr>
      </table>
    </div>
  </div>
</body></html>"""

        msg.attach(MIMEText(plain, "plain"))
        msg.attach(MIMEText(html,  "html"))

        with smtplib.SMTP(smtp_host, smtp_port) as s:
            s.ehlo(); s.starttls(); s.ehlo()
            s.login(smtp_user, smtp_pass)
            s.sendmail(smtp_user, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")
        return False

def notify_all_admins(booking_info):
    """Send booking notification to all admin addresses in the DB."""
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        admins = db.execute("SELECT email FROM admin").fetchall()
        db.close()
        for row in admins:
            send_booking_email(row["email"], booking_info)
    except Exception as e:
        print(f"[NOTIFY ERROR] {e}")

# ═══════════════════════ ROUTES ═══════════════════════════════════════════════

@app.route("/")
def index(): return render_template("index.html")

@app.route("/api/site-status")
def site_status():
    ip = get_ip(); now = time.time()
    st = site_lock_until(); ipt = ip_lock_until(ip)
    if now < st:  return jsonify({"locked":True,"remaining":int(st-now),"scope":"site"})
    if now < ipt: return jsonify({"locked":True,"remaining":int(ipt-now),"scope":"ip"})
    return jsonify({"locked":False,"remaining":0})

# Customer auth
@app.route("/api/customer/login",methods=["POST"])
@lock_check
def customer_login():
    d=request.json or {}; em=(d.get("email") or "").strip().lower(); pw=d.get("password") or ""
    if not em or not pw: return jsonify({"error":"All fields required"}),400
    db=get_db(); row=db.execute("SELECT * FROM customers WHERE email=?",(em,)).fetchone()
    if not row: return jsonify({"error":"Invalid email or password"}),401
    now=time.time()
    if now<float(row["locked_until"]):
        return jsonify({"error":"account_locked","remaining":int(float(row["locked_until"])-now)}),423
    if not check_password_hash(row["password_hash"],pw):
        nf=row["failed_attempts"]+1; lu=0
        if nf>=5: lu=now+300; nf=0
        db.execute("UPDATE customers SET failed_attempts=?,locked_until=? WHERE id=?",(nf,lu,row["id"])); db.commit()
        if lu: return jsonify({"error":"account_locked","remaining":300}),423
        return jsonify({"error":f"Invalid credentials. {5-nf} attempts remaining"}),401
    db.execute("UPDATE customers SET failed_attempts=0,locked_until=0 WHERE id=?",(row["id"],)); db.commit()
    session["customer_id"]=row["id"]; session["customer_name"]=row["username"]
    return jsonify({"success":True,"username":row["username"]})

@app.route("/api/customer/signup",methods=["POST"])
@lock_check
def customer_signup():
    d=request.json or {}; un=(d.get("username") or "").strip()
    em=(d.get("email") or "").strip().lower(); pw=d.get("password") or ""
    if not all([un,em,pw]): return jsonify({"error":"All fields required"}),400
    if not re.match(r"[^@]+@[^@]+\.[^@]+",em): return jsonify({"error":"Invalid email"}),400
    if not pw_valid(pw): return jsonify({"error":"Password needs 8+ chars, uppercase, lowercase, number & special char"}),400
    db=get_db()
    try:
        ph=generate_password_hash(pw,method="pbkdf2:sha256",salt_length=16)
        db.execute("INSERT INTO customers(username,email,password_hash) VALUES(?,?,?)",(un,em,ph)); db.commit()
        row=db.execute("SELECT * FROM customers WHERE email=?",(em,)).fetchone()
        session["customer_id"]=row["id"]; session["customer_name"]=un
        return jsonify({"success":True,"username":un})
    except sqlite3.IntegrityError:
        return jsonify({"error":"Email or username already exists"}),409

@app.route("/api/customer/logout",methods=["POST"])
def customer_logout():
    session.pop("customer_id",None); session.pop("customer_name",None)
    return jsonify({"success":True})

# Admin auth
@app.route("/api/admin/login",methods=["POST"])
@lock_check
def admin_login():
    d=request.json or {}; em=(d.get("email") or "").strip().lower()
    pw=d.get("password") or ""; sw=d.get("secret_word") or ""
    if not all([em,pw,sw]): return jsonify({"error":"All fields required"}),400
    db=get_db(); row=db.execute("SELECT * FROM admin WHERE email=?",(em,)).fetchone()
    if not row: return jsonify({"error":"Invalid credentials"}),401
    now=time.time()
    if now<float(row["locked_until"]):
        return jsonify({"error":"admin_locked","remaining":int(float(row["locked_until"])-now)}),423
    ok=check_password_hash(row["password_hash"],pw) and check_password_hash(row["secret_word_hash"],sw)
    if not ok:
        nf=row["failed_attempts"]+1
        if nf>=2:
            ip=get_ip(); set_site_lock(3600); set_ip_lock(ip,3600,"admin_failure")
            db.execute("UPDATE admin SET failed_attempts=0,locked_until=0 WHERE id=?",(row["id"],)); db.commit()
            return jsonify({"error":"site_locked","remaining":3600}),423
        db.execute("UPDATE admin SET failed_attempts=? WHERE id=?",(nf,row["id"])); db.commit()
        return jsonify({"error":f"Invalid credentials. {2-nf} attempt(s) remaining before 1-hour lockout"}),401
    clear_ip_lock(get_ip())
    db.execute("UPDATE admin SET failed_attempts=0 WHERE id=?",(row["id"],)); db.commit()
    session["admin_pre_auth"]=True; session["admin_id"]=row["id"]
    return jsonify({"success":True,"totp_active":bool(row["totp_active"])})

@app.route("/api/admin/totp-uri")
def admin_totp_uri():
    if not session.get("admin_pre_auth"): return jsonify({"error":"Unauthorized"}),401
    db=get_db(); row=db.execute("SELECT * FROM admin WHERE id=?",(session["admin_id"],)).fetchone()
    if row["totp_active"]: return jsonify({"active":True})
    secret=decrypt(row["totp_secret"])
    return jsonify({"uri":make_totp_uri(secret,row["email"]),"secret":secret,"active":False})

@app.route("/api/admin/qr")
def admin_qr():
    if not session.get("admin_pre_auth"): return jsonify({"error":"Unauthorized"}),401
    db=get_db(); row=db.execute("SELECT * FROM admin WHERE id=?",(session["admin_id"],)).fetchone()
    if row["totp_active"]: return jsonify({"error":"Already active"}),400
    secret=decrypt(row["totp_secret"])
    return send_file(io.BytesIO(make_qr_png(make_totp_uri(secret,row["email"]))),mimetype="image/png")

@app.route("/api/admin/totp-verify",methods=["POST"])
def admin_totp_verify():
    if not session.get("admin_pre_auth"): return jsonify({"error":"Unauthorized"}),401
    code=(request.json or {}).get("code") or ""
    db=get_db(); row=db.execute("SELECT * FROM admin WHERE id=?",(session["admin_id"],)).fetchone()
    if not totp_verify(decrypt(row["totp_secret"]),code):
        return jsonify({"error":"Invalid TOTP code"}),401
    if not row["totp_active"]:
        db.execute("UPDATE admin SET totp_active=1 WHERE id=?",(row["id"],)); db.commit()
    session.pop("admin_pre_auth",None)
    session["admin_authenticated"]=True; session["admin_email"]=row["email"]
    return jsonify({"success":True})

@app.route("/api/admin/logout",methods=["POST"])
def admin_logout():
    for k in ("admin_authenticated","admin_pre_auth","admin_id","admin_email"): session.pop(k,None)
    return jsonify({"success":True})

@app.route("/api/admin/dashboard")
@admin_required
def admin_dashboard():
    db=get_db()
    customers=[dict(r) for r in db.execute("SELECT id,username,email,created_at FROM customers").fetchall()]
    return jsonify({"success":True,"customers":customers})

# Admin: transfers
@app.route("/api/admin/transfers",methods=["GET"])
@admin_required
def get_transfers():
    db=get_db(); rows=db.execute("SELECT * FROM transfers ORDER BY origin,destination").fetchall()
    return jsonify({"transfers":[dict(r) for r in rows]})

@app.route("/api/admin/transfers",methods=["POST"])
@admin_required
def add_transfer():
    d=request.json or {}
    req=["origin","destination","vehicle_class","max_luggage","max_passengers","price_eur"]
    if not all(str(d.get(k,"")).strip() for k in req):
        return jsonify({"error":"All 6 fields required"}),400
    db=get_db()
    cur=db.execute(
        "INSERT INTO transfers(origin,destination,vehicle_class,max_luggage,max_passengers,price_eur,created_by) "
        "VALUES(?,?,?,?,?,?,?)",
        (d["origin"].strip(),d["destination"].strip(),d["vehicle_class"].strip(),
         int(d["max_luggage"]),int(d["max_passengers"]),float(d["price_eur"]),session["admin_id"]))
    db.commit()
    row=db.execute("SELECT * FROM transfers WHERE id=?",(cur.lastrowid,)).fetchone()
    return jsonify({"success":True,"transfer":dict(row)})

@app.route("/api/admin/transfers/<int:tid>",methods=["PUT"])
@admin_required
def update_transfer(tid):
    d=request.json or {}; db=get_db()
    if not db.execute("SELECT id FROM transfers WHERE id=?",(tid,)).fetchone():
        return jsonify({"error":"Not found"}),404
    fields={"origin":d.get("origin"),"destination":d.get("destination"),
            "vehicle_class":d.get("vehicle_class"),"max_luggage":d.get("max_luggage"),
            "max_passengers":d.get("max_passengers"),"price_eur":d.get("price_eur")}
    sets=[]; vals=[]
    for k,v in fields.items():
        if v is not None: sets.append(f"{k}=?"); vals.append(v)
    if not sets: return jsonify({"error":"Nothing to update"}),400
    vals+=[time.time(),tid]
    db.execute(f"UPDATE transfers SET {','.join(sets)},updated_at=? WHERE id=?",vals); db.commit()
    row=db.execute("SELECT * FROM transfers WHERE id=?",(tid,)).fetchone()
    return jsonify({"success":True,"transfer":dict(row)})

@app.route("/api/admin/transfers/<int:tid>",methods=["DELETE"])
@admin_required
def delete_transfer(tid):
    db=get_db(); db.execute("DELETE FROM transfers WHERE id=?",(tid,)); db.commit()
    return jsonify({"success":True})

# Admin: bookings
@app.route("/api/admin/bookings")
@admin_required
def admin_bookings():
    db=get_db()
    rows=db.execute("""
        SELECT b.*,c.username,c.email as customer_email,t.origin,t.destination,t.vehicle_class
        FROM bookings b JOIN customers c ON c.id=b.customer_id JOIN transfers t ON t.id=b.transfer_id
        ORDER BY b.created_at DESC
    """).fetchall()
    return jsonify({"bookings":[dict(r) for r in rows]})

# Admin: earnings
@app.route("/api/admin/earnings")
@admin_required
def admin_earnings():
    db=get_db(); now=datetime.utcnow()
    def qsum(since):
        r=db.execute(
            "SELECT COALESCE(SUM(price_eur),0) as t,COUNT(*) as c FROM bookings "
            "WHERE status='confirmed' AND travel_date>=?",(since,)).fetchone()
        return float(r["t"]),r["c"]
    wt,wc = qsum((now-timedelta(days=7)).strftime("%Y-%m-%d"))
    mt,mc = qsum((now-timedelta(days=30)).strftime("%Y-%m-%d"))
    at,ac = qsum("1970-01-01")
    chart=[]
    for i in range(11,-1,-1):
        ws=(now-timedelta(days=(i+1)*7)).strftime("%Y-%m-%d")
        we=(now-timedelta(days=i*7)).strftime("%Y-%m-%d")
        r=db.execute(
            "SELECT COALESCE(SUM(price_eur),0) as t FROM bookings "
            "WHERE status='confirmed' AND travel_date>=? AND travel_date<?",(ws,we)).fetchone()
        chart.append({"week":we,"total":float(r["t"])})
    return jsonify({"weekly":{"total":wt,"count":wc},"monthly":{"total":mt,"count":mc},
                    "alltime":{"total":at,"count":ac},"chart":chart})

# Customer: transfers
@app.route("/api/transfers/suggest")
def transfer_suggest():
    q=(request.args.get("q") or "").strip().lower()
    field=request.args.get("field","origin")
    if len(q)<2: return jsonify({"suggestions":[]})
    db=get_db(); col="origin" if field=="origin" else "destination"
    rows=db.execute(f"SELECT DISTINCT {col} as name FROM transfers WHERE LOWER({col}) LIKE ? LIMIT 8",(f"%{q}%",)).fetchall()
    return jsonify({"suggestions":[r["name"] for r in rows]})

@app.route("/api/transfers/search")
def transfer_search():
    origin=(request.args.get("origin") or "").strip().lower()
    dest  =(request.args.get("destination") or "").strip().lower()
    pax   =int(request.args.get("passengers") or 0)
    lug   =int(request.args.get("luggage") or 0)
    db=get_db()
    rows=db.execute(
        "SELECT * FROM transfers WHERE LOWER(origin)=? AND LOWER(destination)=? "
        "AND max_passengers>=? AND max_luggage>=?",(origin,dest,pax,lug)).fetchall()
    return jsonify({"transfers":[dict(r) for r in rows]})

@app.route("/api/transfers/price-check")
def transfer_price_check():
    """Public endpoint — no login required. Returns price(s) for a route."""
    origin=(request.args.get("origin") or "").strip().lower()
    dest  =(request.args.get("destination") or "").strip().lower()
    vc    =(request.args.get("vehicle_class") or "").strip().lower()
    if not origin or not dest:
        return jsonify({"transfers":[]})
    db=get_db()
    if vc:
        rows=db.execute(
            "SELECT * FROM transfers WHERE LOWER(origin)=? AND LOWER(destination)=? "
            "AND LOWER(vehicle_class)=?",(origin,dest,vc)).fetchall()
    else:
        rows=db.execute(
            "SELECT * FROM transfers WHERE LOWER(origin)=? AND LOWER(destination)=?",
            (origin,dest)).fetchall()
    return jsonify({"transfers":[dict(r) for r in rows]})

@app.route("/api/customer/book",methods=["POST"])
def customer_book():
    if not session.get("customer_id"): return jsonify({"error":"Not logged in"}),401
    d=request.json or {}; tid=d.get("transfer_id"); date=d.get("travel_date") or ""
    pax=int(d.get("passengers") or 0); lug=int(d.get("luggage") or 0)
    full_name=(d.get("full_name") or "").strip()
    phone=(d.get("phone") or "").strip()
    flight_number=(d.get("flight_number") or "").strip().upper()
    if not all([tid,date,pax]): return jsonify({"error":"Missing fields"}),400
    if not full_name: return jsonify({"error":"Full name is required"}),400
    if not phone: return jsonify({"error":"Phone number is required"}),400
    try: td=datetime.strptime(date,"%Y-%m-%d")
    except ValueError: return jsonify({"error":"Invalid date"}),400
    if td < datetime.utcnow()+timedelta(hours=24):
        return jsonify({"error":"Bookings must be at least 24 hours in advance"}),400
    db=get_db()
    row=db.execute(
        "SELECT * FROM transfers WHERE id=? AND max_passengers>=? AND max_luggage>=?",
        (tid,pax,lug)).fetchone()
    if not row: return jsonify({"error":"Transfer not available for these details"}),404
    db.execute(
        "INSERT INTO bookings(customer_id,transfer_id,travel_date,passengers,luggage,price_eur,full_name,phone,flight_number) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (session["customer_id"],tid,date,pax,lug,row["price_eur"],full_name,phone,flight_number))
    db.commit()
    # Send email notification to all admins
    cust=db.execute("SELECT username,email FROM customers WHERE id=?",(session["customer_id"],)).fetchone()
    notify_all_admins({
        "customer_name": cust["username"] if cust else full_name,
        "customer_email": cust["email"] if cust else "",
        "phone": phone,
        "origin": row["origin"],
        "destination": row["destination"],
        "travel_date": date,
        "vehicle_class": row["vehicle_class"],
        "passengers": pax,
        "luggage": lug,
        "flight_number": flight_number,
        "price_eur": row["price_eur"],
    })
    return jsonify({"success":True,"price_eur":row["price_eur"]})

@app.route("/api/customer/bookings")
def customer_bookings():
    if not session.get("customer_id"): return jsonify({"error":"Not logged in"}),401
    db=get_db()
    rows=db.execute("""
        SELECT b.*,t.origin,t.destination,t.vehicle_class FROM bookings b
        JOIN transfers t ON t.id=b.transfer_id WHERE b.customer_id=? ORDER BY b.travel_date ASC
    """,(session["customer_id"],)).fetchall()
    return jsonify({"bookings":[dict(r) for r in rows]})

if __name__=="__main__":
    init_db()
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
