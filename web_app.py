import io
import os
import re
import time
import sqlite3
import zipfile
import tempfile
import secrets
import threading
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify,
    send_from_directory, send_file, after_this_request,
    session, redirect, url_for
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from PIL import Image, ImageOps, UnidentifiedImageError
import db
import utils

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# PIN bawaan saat database pertama kali dibuat. Akun yang masih memakai PIN ini wajib ganti PIN.
PIN_BAWAAN = {"admin": "1234", "kasir": "0000"}
PESAN_PIN_KASIR_BELUM_DIATUR = "PIN kasir belum diatur admin. Minta admin mengatur PIN kasir lewat menu PIN, lalu coba masuk lagi."


def muat_atau_buat_secret_key():
    """Membaca secret key dari file tersembunyi, atau membuat kunci acak 256-bit baru."""
    path_kunci = os.path.join(BASE_DIR, ".secret_key")
    if os.path.exists(path_kunci):
        with open(path_kunci, "r", encoding="utf-8") as f:
            kunci = f.read().strip()
            if len(kunci) >= 32:
                return kunci

    kunci_baru = secrets.token_hex(32)
    with open(path_kunci, "w", encoding="utf-8") as f:
        f.write(kunci_baru)
    try:
        os.chmod(path_kunci, 0o600)
    except OSError:
        pass
    return kunci_baru


app = Flask(__name__)

# Di belakang reverse proxy (mis. PythonAnywhere), percayai satu hop X-Forwarded-For saja.
# Di luar itu, header X-Forwarded-For dan X-Real-IP diabaikan agar IP pengunjung tidak bisa dipalsukan.
DI_BELAKANG_PROXY = os.environ.get("PETSHOP_BEHIND_PROXY") == "1" or "PYTHONANYWHERE_DOMAIN" in os.environ
if DI_BELAKANG_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # Maksimal upload 5 MB


@app.errorhandler(413)
def file_terlalu_besar(e):
    return jsonify({"ok": False, "pesan": "Ukuran foto terlalu besar (maksimal 5 MB)"}), 413

app.secret_key = muat_atau_buat_secret_key()
app.permanent_session_lifetime = timedelta(days=30)

# Pengamanan cookie sesi
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=("PYTHONANYWHERE_DOMAIN" in os.environ)
)

# ==================== KEAMANAN: CSRF & SECURITY HEADERS ====================

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token()}


# Endpoint yang tetap boleh dibuka saat admin masih memakai PIN bawaan
ENDPOINT_SAAT_WAJIB_GANTI_PIN = ("static", "ganti_pin_saya", "logout")


@app.before_request
def validasi_sesi_dan_csrf():
    # 1. Cek keaslian sesi aktif via session_version (hanguskan jika akun dihapus atau PIN diganti)
    if request.endpoint not in ("static", "login") and "username" in session:
        conn = db.get_connection()
        user = conn.execute(
            "SELECT role, COALESCE(session_version, 1) AS session_version, wajib_ganti_pin "
            "FROM users WHERE username = ?",
            (session["username"],)
        ).fetchone()

        if not user or user["session_version"] != session.get("session_version"):
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "pesan": "Sesi berakhir karena PIN telah diperbarui. Silakan login ulang."}), 401
            return redirect(url_for("login"))

        session["role"] = user["role"]

        # 2. PIN kasir hanya diatur admin: sesi kasir yang masih PIN bawaan dihentikan
        if user["wajib_ganti_pin"] and user["role"] == "kasir":
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "pesan": PESAN_PIN_KASIR_BELUM_DIATUR}), 401
            return render_template("login.html", error=PESAN_PIN_KASIR_BELUM_DIATUR,
                                   sisa_detik=0, username=""), 403

        # Admin yang masih memakai PIN bawaan hanya boleh membuka halaman ganti PIN
        if user["wajib_ganti_pin"] and request.endpoint not in ENDPOINT_SAAT_WAJIB_GANTI_PIN:
            if request.path.startswith("/api/"):
                return jsonify({
                    "ok": False,
                    "pesan": "Ganti PIN bawaan dulu sebelum memakai aplikasi.",
                    "wajib_ganti_pin": True
                }), 403
            return redirect(url_for("ganti_pin_saya"))

    # 3. Validasi CSRF untuk semua request pengubah data (termasuk POST /logout)
    if request.method in ("POST", "PUT", "DELETE"):
        token_sesi = session.get("csrf_token", "")
        token_req = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")

        if not token_sesi or not token_req or not secrets.compare_digest(token_sesi, token_req):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "pesan": "Sesi keamanan tidak valid. Muat ulang halaman."}), 403
            return "Permintaan tidak valid (CSRF token mismatch). Silakan kembali dan muat ulang halaman.", 403


@app.after_request
def tambah_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(self)"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )

    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response

# ==================== KEAMANAN: ANTI BRUTE-FORCE LOGIN ====================
BATAS_GAGAL_LOGIN = 5                               # kegagalan per akun dalam jendela waktu sebelum dikunci
BATAS_GAGAL_PER_IP = 20                             # batas per IP dibuat longgar agar jaringan toko yang berbagi satu IP tidak ikut terkunci
JENDELA_GAGAL_DETIK = 15 * 60                       # kegagalan lebih tua dari 15 menit tidak dihitung lagi
DURASI_KUNCI_BERTAHAP = (5 * 60, 15 * 60, 60 * 60)  # kunci naik bertahap: 5, 15, lalu 60 menit
TENANG_RESET_DETIK = 24 * 60 * 60                   # tanpa kunci selama 24 jam, tingkat kunci kembali ke awal

PELACAK_GAGAL = {}
_pelacak_lock = threading.Lock()


def get_client_ip():
    """IP pengunjung. X-Forwarded-For hanya dipercaya jika aplikasi berada di belakang proxy (lihat ProxyFix)."""
    return request.remote_addr or "unknown"


def format_sisa_waktu(detik):
    menit, sisa_detik = divmod(max(1, int(detik)), 60)
    if menit > 0:
        return f"{menit} menit {sisa_detik} detik"
    return f"{sisa_detik} detik"


def _daftar_pelacak(ruang, ip, username):
    """Kunci yang dihitung: per IP (batas longgar) dan per akun (batas ketat)."""
    daftar = [(f"{ruang}:ip:{ip}", BATAS_GAGAL_PER_IP)]
    if username:
        daftar.append((f"{ruang}:user:{username.lower()}", BATAS_GAGAL_LOGIN))
    return daftar


def _entri_pelacak(kunci):
    return PELACAK_GAGAL.setdefault(kunci, {
        "gagal": [], "terkunci_sampai": 0.0, "jumlah_kunci": 0, "kunci_terakhir": 0.0
    })


def _bersihkan_pelacak(sekarang):
    """Membuang entri yang sudah tidak aktif agar memori tidak terus membesar."""
    if len(PELACAK_GAGAL) < 1000:
        return
    for kunci in list(PELACAK_GAGAL):
        e = PELACAK_GAGAL[kunci]
        aktif = (
            e["terkunci_sampai"] > sekarang
            or any(sekarang - t < JENDELA_GAGAL_DETIK for t in e["gagal"])
            or sekarang - e["kunci_terakhir"] <= TENANG_RESET_DETIK
        )
        if not aktif:
            del PELACAK_GAGAL[kunci]


def cek_kunci(ruang, ip, username=""):
    """Sisa detik kunci (0 jika tidak terkunci). Kunci IP dan kunci akun sama-sama diperiksa."""
    sekarang = time.time()
    sisa = 0
    with _pelacak_lock:
        for kunci, _batas in _daftar_pelacak(ruang, ip, username):
            e = PELACAK_GAGAL.get(kunci)
            if e and e["terkunci_sampai"] > sekarang:
                sisa = max(sisa, int(e["terkunci_sampai"] - sekarang) + 1)
    return sisa


def catat_gagal(ruang, ip, username=""):
    """Mencatat satu kegagalan. Mengembalikan True jika kegagalan ini memicu kunci baru."""
    sekarang = time.time()
    kunci_baru = False
    with _pelacak_lock:
        _bersihkan_pelacak(sekarang)
        for kunci, batas in _daftar_pelacak(ruang, ip, username):
            e = _entri_pelacak(kunci)
            e["gagal"] = [t for t in e["gagal"] if sekarang - t < JENDELA_GAGAL_DETIK]
            e["gagal"].append(sekarang)
            if len(e["gagal"]) >= batas and e["terkunci_sampai"] <= sekarang:
                if sekarang - e["kunci_terakhir"] > TENANG_RESET_DETIK:
                    e["jumlah_kunci"] = 0
                durasi = DURASI_KUNCI_BERTAHAP[min(e["jumlah_kunci"], len(DURASI_KUNCI_BERTAHAP) - 1)]
                e["terkunci_sampai"] = sekarang + durasi
                e["jumlah_kunci"] += 1
                e["kunci_terakhir"] = sekarang
                e["gagal"] = []
                kunci_baru = True
    return kunci_baru


def hitung_gagal_akun(ruang, username=""):
    """Jumlah kegagalan akun dalam jendela waktu, dipakai untuk menghitung sisa percobaan."""
    if not username:
        return 0
    sekarang = time.time()
    with _pelacak_lock:
        e = PELACAK_GAGAL.get(f"{ruang}:user:{username.lower()}")
        if not e:
            return 0
        return len([t for t in e["gagal"] if sekarang - t < JENDELA_GAGAL_DETIK])


def reset_gagal(ruang, ip, username=""):
    with _pelacak_lock:
        for kunci, _batas in _daftar_pelacak(ruang, ip, username):
            PELACAK_GAGAL.pop(kunci, None)


# --- Login ---
def cek_status_blokir_login(ip, username=""):
    sisa = cek_kunci("login", ip, username)
    return (sisa > 0), sisa


def catat_kegagalan_login(ip, username=""):
    """Mencatat kegagalan login. Mengembalikan jumlah kegagalan akun dalam jendela waktu."""
    if catat_gagal("login", ip, username):
        catat_audit(
            "LOGIN_TERKUNCI",
            f"Terblokir sementara setelah {BATAS_GAGAL_LOGIN}x gagal (IP: {ip})",
            username=username or "unknown"
        )
    return hitung_gagal_akun("login", username)


def reset_kegagalan_login(ip, username=""):
    reset_gagal("login", ip, username)


# --- Ubah PIN (ubah PIN admin dan ganti PIN sendiri) ---
def _cek_blokir_ubah_pin(ip, username):
    sisa = cek_kunci("ubah_pin", ip, username)
    return (sisa > 0), sisa


def _catat_gagal_ubah_pin(ip, username, target_user):
    kunci_baru = catat_gagal("ubah_pin", ip, username)
    catat_audit(
        "UBAH_PIN_GAGAL",
        f"PIN lama salah saat mengubah PIN akun '{target_user}' (IP: {ip})",
        username=username
    )
    if kunci_baru:
        catat_audit(
            "UBAH_PIN_TERKUNCI",
            f"Fitur ubah PIN dikunci sementara setelah {BATAS_GAGAL_LOGIN}x gagal (IP: {ip})",
            username=username
        )
    return hitung_gagal_akun("ubah_pin", username)


def _reset_gagal_ubah_pin(ip, username):
    reset_gagal("ubah_pin", ip, username)


FOLDER_IMG = os.path.join(BASE_DIR, "img_produk")
os.makedirs(FOLDER_IMG, exist_ok=True)

if hasattr(db, "init_db"):
    db.init_db()


def is_pin_hashed(pin_str):
    return isinstance(pin_str, str) and pin_str.startswith(("scrypt:", "pbkdf2:"))


def verifikasi_pin_db(pin_tersimpan, pin_input):
    if not pin_tersimpan or not pin_input:
        return False
    if is_pin_hashed(pin_tersimpan):
        return check_password_hash(pin_tersimpan, pin_input)
    return pin_tersimpan == pin_input


def pastikan_kolom(tabel, kolom, definisi):
    """Menambahkan kolom hanya jika belum ada, tanpa menelan error lain."""
    conn = db.get_connection()
    kolom_ada = {r["name"] for r in conn.execute(f"PRAGMA table_info({tabel})").fetchall()}
    if kolom not in kolom_ada:
        conn.execute(f"ALTER TABLE {tabel} ADD COLUMN {kolom} {definisi}")
        conn.commit()


def sinkronkan_flag_pin_bawaan():
    """Menandai akun yang masih memakai PIN bawaan (wajib_ganti_pin = 1). Dijalankan setiap startup."""
    conn = db.get_connection()
    for r in conn.execute("SELECT id, username, pin FROM users").fetchall():
        bawaan = PIN_BAWAAN.get(r["username"])
        masih_bawaan = bool(bawaan) and verifikasi_pin_db(r["pin"], bawaan)
        conn.execute(
            "UPDATE users SET wajib_ganti_pin = ? WHERE id = ?",
            (1 if masih_bawaan else 0, r["id"])
        )
    conn.commit()


def inisialisasi_skema_lengkap():
    """Memastikan seluruh tabel dan kolom fitur lengkap tersedia tanpa menghapus data lama."""
    conn = db.get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pin TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO users (username, pin, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("1234"), "admin")
        )
        cur.execute(
            "INSERT INTO users (username, pin, role) VALUES (?, ?, ?)",
            ("kasir", generate_password_hash("0000"), "kasir")
        )

    cur.execute("""
        CREATE TABLE IF NOT EXISTS kategori (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama TEXT UNIQUE NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS produk (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama TEXT NOT NULL,
            kategori TEXT DEFAULT '',
            harga_beli REAL DEFAULT 0,
            harga_jual REAL NOT NULL,
            stok INTEGER NOT NULL DEFAULT 0,
            satuan TEXT DEFAULT 'pcs',
            gambar TEXT DEFAULT '',
            expired_date TEXT DEFAULT ''
        )
    """)

    for col_sql in [
        "ALTER TABLE produk ADD COLUMN harga_beli REAL DEFAULT 0",
        "ALTER TABLE produk ADD COLUMN gambar TEXT DEFAULT ''",
        "ALTER TABLE produk ADD COLUMN expired_date TEXT DEFAULT ''"
    ]:
        try:
            cur.execute(col_sql)
        except Exception:
            pass

    cur.execute("""
        CREATE TABLE IF NOT EXISTS barang_masuk (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            produk_id INTEGER,
            tanggal TEXT,
            jumlah INTEGER,
            harga_beli REAL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS transaksi (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tanggal TEXT,
            total REAL DEFAULT 0,
            bayar REAL DEFAULT 0,
            kembalian REAL DEFAULT 0,
            keuntungan REAL DEFAULT 0
        )
    """)

    for col_sql in [
        "ALTER TABLE transaksi ADD COLUMN bayar REAL DEFAULT 0",
        "ALTER TABLE transaksi ADD COLUMN status TEXT DEFAULT 'selesai'",
        "ALTER TABLE users ADD COLUMN session_version INTEGER DEFAULT 1"
    ]:
        try:
            cur.execute(col_sql)
        except Exception:
            pass

    trx_cols_init = [r["name"] for r in cur.execute("PRAGMA table_info(transaksi)").fetchall()]
    if "dibayar" in trx_cols_init and "bayar" in trx_cols_init:
        cur.execute("UPDATE transaksi SET bayar = dibayar WHERE (bayar IS NULL OR bayar = 0) AND dibayar > 0")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS transaksi_detail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaksi_id INTEGER,
            produk_id INTEGER,
            nama_produk TEXT,
            harga_beli REAL DEFAULT 0,
            harga_satuan REAL DEFAULT 0,
            jumlah INTEGER DEFAULT 0,
            subtotal REAL DEFAULT 0
        )
    """)

    # Index untuk subquery "produk belum terjual" dan laporan per produk
    cur.execute("CREATE INDEX IF NOT EXISTS idx_transaksi_detail_produk ON transaksi_detail(produk_id)")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tanggal TEXT NOT NULL,
            username TEXT NOT NULL,
            aksi TEXT NOT NULL,
            detail TEXT DEFAULT ''
        )
    """)

    try:
        cur.execute("ALTER TABLE users ADD COLUMN session_version INTEGER DEFAULT 1")
    except Exception:
        pass

    try:
        cur.execute("ALTER TABLE transaksi_detail ADD COLUMN harga_beli REAL DEFAULT 0")
    except Exception:
        pass

    trx_cols_after = [r["name"] for r in cur.execute("PRAGMA table_info(transaksi)").fetchall()]
    if "keuntungan" in trx_cols_after:
        col_tot = "total" if "total" in trx_cols_after else "total_harga"
        cur.execute(f"""
            UPDATE transaksi
            SET keuntungan = (
                SELECT COALESCE(SUM((td.harga_satuan - td.harga_beli) * td.jumlah), 0)
                FROM transaksi_detail td
                WHERE td.transaksi_id = transaksi.id
            )
            WHERE keuntungan IS NULL OR (keuntungan = 0 AND COALESCE({col_tot}, 0) > 0)
        """)

    conn.commit()


def migrasi_hash_pin():
    """Otomatis mengenkripsi PIN lama yang masih berbentuk teks biasa di database."""
    conn = db.get_connection()
    rows = conn.execute("SELECT id, pin FROM users").fetchall()
    ada_perubahan = False
    for r in rows:
        pin_lama = str(r["pin"] or "")
        if pin_lama and not is_pin_hashed(pin_lama):
            pin_hash = generate_password_hash(pin_lama)
            conn.execute("UPDATE users SET pin = ? WHERE id = ?", (pin_hash, r["id"]))
            ada_perubahan = True
    if ada_perubahan:
        conn.commit()


inisialisasi_skema_lengkap()
pastikan_kolom("users", "wajib_ganti_pin", "INTEGER NOT NULL DEFAULT 0")
migrasi_hash_pin()
sinkronkan_flag_pin_bawaan()

WIB = timezone(timedelta(hours=7))  # Waktu Indonesia Barat (UTC+7). Tidak ada jam musim panas.


def sekarang_wib():
    """Waktu sekarang di Indonesia Barat, tanpa zona waktu, untuk disimpan sebagai 'YYYY-MM-DD HH:MM:SS'."""
    return datetime.now(WIB).replace(tzinfo=None)


def catat_audit(aksi, detail="", username=None):
    """Mencatat aktivitas sensitif ke tabel audit_log."""
    user_aktif = username or session.get("username") or "system"
    waktu = sekarang_wib().strftime("%Y-%m-%d %H:%M:%S")
    conn = db.get_connection()
    try:
        conn.execute(
            "INSERT INTO audit_log (tanggal, username, aksi, detail) VALUES (?, ?, ?, ?)",
            (waktu, user_aktif, aksi, detail)
        )
        conn.execute("""
            DELETE FROM audit_log
            WHERE id NOT IN (SELECT id FROM audit_log ORDER BY id DESC LIMIT 5000)
        """)
        conn.commit()
    except Exception:
        pass


def get_table_columns(table_name):
    conn = db.get_connection()
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return [r["name"] for r in rows]


def cek_kredensial(username, pin):
    conn = db.get_connection()
    user = conn.execute(
        "SELECT pin, role, COALESCE(session_version, 1) AS session_version FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    if user and verifikasi_pin_db(user["pin"], pin):
        return user["role"], int(user["session_version"])
    return None, None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "role" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "pesan": "Sesi habis, silakan login ulang"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify({"ok": False, "pesan": "Akses ditolak: khusus Admin"}), 403
        return f(*args, **kwargs)
    return decorated


def hapus_file_foto(nama_file):
    nama_aman = os.path.basename(nama_file) if nama_file else ""
    if not nama_aman:
        return
    path_foto = os.path.join(FOLDER_IMG, nama_aman)
    if os.path.exists(path_foto):
        try:
            os.remove(path_foto)
        except OSError:
            pass


def proses_dan_kompres_foto(file_storage, foto_lama=""):
    if not file_storage or not file_storage.filename:
        return foto_lama

    ekstensi = os.path.splitext(file_storage.filename)[1].lower()
    if ekstensi not in (".jpg", ".jpeg", ".png", ".webp"):
        raise ValueError("Format gambar harus JPG, PNG, atau WEBP.")

    try:
        file_storage.stream.seek(0)
        with Image.open(file_storage.stream) as img_cek:
            img_cek.verify()

        file_storage.stream.seek(0)
        with Image.open(file_storage.stream) as img:
            img = ImageOps.exif_transpose(img)
            if img.mode in ("RGBA", "LA", "P"):
                latar = Image.new("RGB", img.size, (255, 255, 255))
                if img.mode == "P":
                    img = img.convert("RGBA")
                latar.paste(img, mask=img.split()[-1])
                img = latar
            elif img.mode != "RGB":
                img = img.convert("RGB")

            img.thumbnail((300, 300), Image.Resampling.LANCZOS)
            nama_file_baru = f"prod_{int(time.time() * 1000)}_{secrets.token_hex(3)}.jpg"
            path_simpan = os.path.join(FOLDER_IMG, nama_file_baru)
            img.save(path_simpan, "JPEG", optimize=True, quality=80)
    except (UnidentifiedImageError, OSError, ValueError):
        raise ValueError("File gambar rusak atau bukan file gambar yang valid.")

    return nama_file_baru


def catat_restock_aman(produk_id, jumlah, harga_beli):
    """Dipanggil SETELAH produk tersimpan. Kegagalan mencatat barang masuk tidak boleh
    membuat respons simpan produk menjadi error, karena produknya sudah tersimpan."""
    try:
        catat_restock(produk_id, jumlah, harga_beli)
    except Exception:
        app.logger.exception("Gagal mencatat riwayat barang masuk")


def catat_restock(produk_id, jumlah, harga_beli):
    if jumlah <= 0:
        return
    conn = db.get_connection()
    tanggal = sekarang_wib().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        "INSERT INTO barang_masuk (produk_id, tanggal, jumlah, harga_beli) VALUES (?, ?, ?, ?)",
        (produk_id, tanggal, jumlah, harga_beli)
    )
    conn.commit()


# ==================== ROUTE LOGIN & HALAMAN UTAMA ====================

@app.route("/login", methods=["GET", "POST"])
def login():
    if "role" in session:
        return redirect(url_for("index"))

    ip = get_client_ip()
    username_form = request.form.get("username", "").strip().lower() if request.method == "POST" else ""
    terkunci, sisa_detik = cek_status_blokir_login(ip, username_form)

    if terkunci:
        pesan_blokir = f"Terlalu banyak percobaan gagal. Coba lagi dalam {format_sisa_waktu(sisa_detik)}."
        status_code = 429 if request.method == "POST" else 200
        return render_template(
            "login.html",
            error=pesan_blokir,
            sisa_detik=sisa_detik,
            username=username_form
        ), status_code

    error = None
    if request.method == "POST":
        username = username_form
        pin = request.form.get("pin", "").strip()
        role, session_version = cek_kredensial(username, pin)

        if role == "kasir" and pin == PIN_BAWAAN["kasir"]:
            # PIN kasir hanya diatur admin: selama masih PIN bawaan, kasir tidak boleh masuk
            return render_template(
                "login.html",
                error=PESAN_PIN_KASIR_BELUM_DIATUR,
                sisa_detik=0,
                username=username
            ), 403

        if role:
            reset_kegagalan_login(ip, username)
            session.clear()
            session.permanent = True
            session["username"] = username
            session["role"] = role
            session["session_version"] = session_version
            session["csrf_token"] = secrets.token_hex(32)
            catat_audit("LOGIN_SUKSES", f"Masuk sebagai {role}", username=username)
            return redirect(url_for("index"))
        else:
            time.sleep(0.5)
            jumlah_gagal = catat_kegagalan_login(ip, username)
            terkunci_sekarang, sisa_kunci = cek_status_blokir_login(ip, username)
            if terkunci_sekarang:
                error = f"Terlalu banyak percobaan gagal. Coba lagi dalam {format_sisa_waktu(sisa_kunci)}."
                return render_template(
                    "login.html",
                    error=error,
                    sisa_detik=sisa_kunci,
                    username=username
                ), 429
            sisa_coba = BATAS_GAGAL_LOGIN - jumlah_gagal
            error = f"Username atau PIN salah! Sisa percobaan: {sisa_coba} kali."

    return render_template("login.html", error=error, sisa_detik=0, username=username_form)


@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("username")
    if username:
        catat_audit("LOGOUT", "Keluar dari sistem", username=username)
    session.clear()
    return jsonify({"ok": True, "redirect": url_for("login")})

@app.route("/ganti-pin", methods=["GET", "POST"])
@login_required
@admin_required
def ganti_pin_saya():
    """Ganti PIN akun admin sendiri. PIN kasir hanya diatur admin lewat menu PIN."""
    username = session.get("username", "")
    conn = db.get_connection()
    baris_user = conn.execute(
        "SELECT wajib_ganti_pin FROM users WHERE username = ?", (username,)
    ).fetchone()
    wajib = bool(baris_user and baris_user["wajib_ganti_pin"])
    error = None
    status = 200

    if request.method == "POST":
        ip = get_client_ip()
        terkunci, sisa_detik = _cek_blokir_ubah_pin(ip, username)
        if terkunci:
            error = f"Terlalu banyak percobaan salah. Coba lagi dalam {format_sisa_waktu(sisa_detik)}."
            status = 429
        else:
            pin_lama = request.form.get("pin_lama", "").strip()
            pin_baru = request.form.get("pin_baru", "").strip()
            pin_konfirmasi = request.form.get("pin_konfirmasi", "").strip()
            baris_pin = conn.execute("SELECT pin FROM users WHERE username = ?", (username,)).fetchone()

            if not baris_pin or not verifikasi_pin_db(baris_pin["pin"], pin_lama):
                time.sleep(0.5)
                jml_gagal = _catat_gagal_ubah_pin(ip, username, username)
                terkunci_sekarang, sisa_kunci = _cek_blokir_ubah_pin(ip, username)
                if terkunci_sekarang:
                    error = f"Terlalu banyak percobaan salah. Coba lagi dalam {format_sisa_waktu(sisa_kunci)}."
                    status = 429
                else:
                    error = f"PIN saat ini salah! Sisa percobaan: {BATAS_GAGAL_LOGIN - jml_gagal} kali."
                    status = 403
            elif not re.fullmatch(r"[0-9]{4,6}", pin_baru):
                error = "PIN baru harus berupa 4 sampai 6 digit angka."
                status = 400
            elif pin_baru in PIN_BAWAAN.values():
                error = "Jangan gunakan PIN bawaan (1234 atau 0000)."
                status = 400
            elif pin_baru == pin_lama:
                error = "PIN baru harus berbeda dari PIN saat ini."
                status = 400
            elif pin_baru != pin_konfirmasi:
                error = "Konfirmasi PIN baru tidak cocok."
                status = 400
            else:
                _reset_gagal_ubah_pin(ip, username)
                conn.execute(
                    "UPDATE users SET pin = ?, wajib_ganti_pin = 0, "
                    "session_version = COALESCE(session_version, 1) + 1 WHERE username = ?",
                    (generate_password_hash(pin_baru), username)
                )
                conn.commit()
                sv_baru = conn.execute(
                    "SELECT COALESCE(session_version, 1) AS sv FROM users WHERE username = ?",
                    (username,)
                ).fetchone()["sv"]
                session["session_version"] = int(sv_baru)
                catat_audit("UBAH_PIN", f"Mengganti PIN sendiri ('{username}')", username=username)
                return redirect(url_for("index"))

    return render_template("ganti_pin.html", username=username, wajib=wajib, error=error), status


def cek_status_pin_default():
    """Status PIN bawaan dibaca dari flag wajib_ganti_pin (tanpa verifikasi hash tiap halaman dibuka)."""
    conn = db.get_connection()
    rows = conn.execute(
        "SELECT username, wajib_ganti_pin FROM users WHERE username IN ('admin', 'kasir')"
    ).fetchall()
    flag = {r["username"]: bool(r["wajib_ganti_pin"]) for r in rows}
    return {
        "admin_default": flag.get("admin", False),
        "kasir_default": flag.get("kasir", False),
    }


@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        role=session.get("role", "kasir"),
        username=session.get("username", "kasir"),
        pin_status=cek_status_pin_default()
    )


@app.route("/img_produk/<path:filename>")
@login_required
def serve_gambar(filename):
    return send_from_directory(FOLDER_IMG, filename)


# ==================== API PRODUK & STOK ====================

@app.route("/api/produk", methods=["GET"])
@login_required
def api_get_produk():
    conn = db.get_connection()
    keyword = request.args.get("q", "").strip()
    kategori = request.args.get("kategori", "Semua Kategori").strip()
    filter_khusus = request.args.get("filter", "semua").strip()
    if filter_khusus not in ("", "semua") and session.get("role") != "admin":
        return jsonify({"ok": False, "pesan": "Akses ditolak: laporan stok khusus Admin"}), 403
    sort_by = request.args.get("sort", "nama").strip()
    try:
        page = max(1, int(request.args.get("page", 1) or 1))
    except (TypeError, ValueError):
        page = 1

    try:
        limit = max(0, min(500, int(request.args.get("limit", 0) or 0)))
    except (TypeError, ValueError):
        limit = 0

    where_clauses = ["1=1"]
    params = []

    if keyword:
        where_clauses.append("p.nama LIKE ?")
        params.append(f"%{keyword}%")

    if kategori and kategori != "Semua Kategori":
        where_clauses.append("p.kategori = ?")
        params.append(kategori)

    if filter_khusus == "menipis":
        where_clauses.append("p.stok <= 5")
    elif filter_khusus == "expired":
        batas_exp = (sekarang_wib() + timedelta(days=90)).strftime("%Y-%m-%d")
        where_clauses.append("p.expired_date IS NOT NULL AND p.expired_date != '' AND p.expired_date <= ?")
        params.append(batas_exp)
    elif filter_khusus == "dead_stock":
        batas_30 = (sekarang_wib() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        where_clauses.append("""
            NOT EXISTS (
                -- NOT EXISTS aman untuk produk_id NULL dari produk yang sudah dihapus
                SELECT 1
                FROM transaksi_detail td
                JOIN transaksi t ON td.transaksi_id = t.id
                WHERE td.produk_id = p.id
                  AND t.tanggal >= ?
                  AND COALESCE(t.status, 'selesai') != 'retur'
            )
        """)
        params.append(batas_30)

    where_sql = " AND ".join(where_clauses)

    total_items = conn.execute(
        f"SELECT COUNT(*) as total FROM produk p WHERE {where_sql}",
        params
    ).fetchone()["total"]

    order_map = {
        "nama": "LOWER(p.nama) ASC",
        "stok_asc": "p.stok ASC, LOWER(p.nama) ASC",
        "harga_desc": "p.harga_jual DESC, LOWER(p.nama) ASC",
        "expired_asc": "CASE WHEN p.expired_date IS NULL OR p.expired_date = '' THEN 1 ELSE 0 END, p.expired_date ASC"
    }
    order_sql = order_map.get(sort_by, "LOWER(p.nama) ASC")

    query = f"SELECT p.* FROM produk p WHERE {where_sql} ORDER BY {order_sql}"
    query_params = list(params)

    total_pages = 1
    if limit > 0:
        total_pages = max(1, (total_items + limit - 1) // limit)
        page = min(page, total_pages)
        offset = (page - 1) * limit
        query += " LIMIT ? OFFSET ?"
        query_params.extend([limit, offset])

    rows = conn.execute(query, query_params).fetchall()
    produk = [dict(r) for r in rows]

    # Sembunyikan harga modal jika login sebagai kasir
    if session.get("role") != "admin":
        produk = [{k: v for k, v in p.items() if k != "harga_beli"} for p in produk]

    kat_rows = conn.execute("SELECT id, nama FROM kategori ORDER BY LOWER(nama)").fetchall()
    kategori_lengkap = [dict(k) for k in kat_rows]

    return jsonify({
        "produk": produk,
        "kategori": [k["nama"] for k in kategori_lengkap],
        "kategori_lengkap": kategori_lengkap,
        "page": page,
        "total_pages": total_pages,
        "total_items": total_items
    })


@app.route("/api/produk/terkini", methods=["GET"])
@login_required
def api_produk_terkini():
    """Harga jual & stok terbaru untuk produk tertentu, dipakai kasir sebelum bayar.
    Sengaja tidak menyertakan harga_beli supaya aman untuk role kasir."""
    try:
        ids = sorted({int(x) for x in request.args.get("ids", "").split(",") if x.strip()})
    except ValueError:
        return jsonify({"ok": False, "pesan": "Daftar produk tidak valid"}), 400

    if not ids:
        return jsonify({"ok": True, "produk": []})
    if len(ids) > 200:
        return jsonify({"ok": False, "pesan": "Terlalu banyak item dalam keranjang"}), 400

    conn = db.get_connection()
    placeholder = ",".join("?" * len(ids))
    rows = conn.execute(
        f"SELECT id, nama, harga_jual, stok, satuan FROM produk WHERE id IN ({placeholder})",
        ids
    ).fetchall()
    return jsonify({"ok": True, "produk": [dict(r) for r in rows]})


@app.route("/api/produk", methods=["POST"])
@login_required
@admin_required
def api_simpan_produk():
    conn = db.get_connection()
    foto_baru_tersimpan = ""
    sudah_commit = False  # True setelah produk tersimpan ke database
    try:
        produk_id = request.form.get("id", "").strip()
        nama = request.form.get("nama", "").strip()
        kategori = request.form.get("kategori", "").strip()
        satuan = request.form.get("satuan", "pcs").strip() or "pcs"
        expired_date = request.form.get("expired_date", "").strip()

        if not nama:
            return jsonify({"ok": False, "pesan": "Nama produk wajib diisi"}), 400
        if len(nama) > 120 or len(kategori) > 60 or len(satuan) > 30:
            return jsonify({"ok": False, "pesan": "Teks nama, kategori, atau satuan terlalu panjang"}), 400

        if expired_date:
            format_valid = False
            for fmt in ("%Y-%m-%d", "%Y-%m"):
                try:
                    datetime.strptime(expired_date, fmt)
                    format_valid = True
                    break
                except ValueError:
                    continue
            if not format_valid:
                return jsonify({
                    "ok": False,
                    "pesan": "Format tanggal expired tidak valid (gunakan YYYY-MM-DD, contoh: 2026-12-31)"
                }), 400

        try:
            harga_beli = int(float(request.form.get("harga_beli", 0) or 0))
            harga_jual = int(float(request.form.get("harga_jual", 0) or 0))
            stok = int(float(request.form.get("stok", 0) or 0))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "pesan": "Harga dan stok harus berupa angka yang valid"}), 400

        if harga_beli < 0 or harga_jual < 0 or stok < 0:
            return jsonify({"ok": False, "pesan": "Harga modal, harga jual, dan stok tidak boleh negatif"}), 400

        lama = None
        foto_lama_db = ""
        if produk_id:
            pid = int(produk_id)
            lama = conn.execute(
                "SELECT nama, stok, harga_beli, harga_jual, gambar FROM produk WHERE id = ?",
                (pid,)
            ).fetchone()
            if not lama:
                return jsonify({"ok": False, "pesan": "Produk tidak ditemukan"}), 404
            foto_lama_db = lama["gambar"] or ""

            duplikat = conn.execute(
                "SELECT id FROM produk WHERE LOWER(nama) = LOWER(?) AND id != ?",
                (nama, pid)
            ).fetchone()
        else:
            duplikat = conn.execute(
                "SELECT id FROM produk WHERE LOWER(nama) = LOWER(?)",
                (nama,)
            ).fetchone()

        if duplikat:
            return jsonify({
                "ok": False,
                "pesan": f"Produk '{nama}' sudah ada! Gunakan nama lebih spesifik (misal ukuran/varian)."
            }), 400

        if kategori:
            conn.execute("INSERT OR IGNORE INTO kategori (nama) VALUES (?)", (kategori,))

        file_foto = request.files.get("gambar")
        nama_gambar = proses_dan_kompres_foto(file_foto, foto_lama_db)
        if nama_gambar != foto_lama_db:
            foto_baru_tersimpan = nama_gambar

        if lama:
            pid = int(produk_id)
            stok_lama = lama["stok"]

            conn.execute("""
                UPDATE produk
                SET nama=?, kategori=?, harga_beli=?, harga_jual=?, stok=?, satuan=?, gambar=?, expired_date=?
                WHERE id=?
            """, (nama, kategori, harga_beli, harga_jual, stok, satuan, nama_gambar, expired_date, pid))
            conn.commit()
            sudah_commit = True

            if foto_baru_tersimpan and foto_lama_db:
                hapus_file_foto(foto_lama_db)

            if stok > stok_lama:
                catat_restock_aman(pid, stok - stok_lama, harga_beli)

            perubahan = []
            if stok != lama["stok"]:
                perubahan.append(f"stok {lama['stok']}→{stok}")
            if harga_beli != int(lama["harga_beli"] or 0):
                perubahan.append(f"modal {int(lama['harga_beli'] or 0)}→{harga_beli}")
            if harga_jual != int(lama["harga_jual"] or 0):
                perubahan.append(f"jual {int(lama['harga_jual'] or 0)}→{harga_jual}")
            if perubahan:
                catat_audit("UBAH_PRODUK", f"'{nama}' (ID #{pid}): {', '.join(perubahan)}")

            id_terbaru = pid
        else:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO produk (nama, kategori, harga_beli, harga_jual, stok, satuan, gambar, expired_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (nama, kategori, harga_beli, harga_jual, stok, satuan, nama_gambar, expired_date))
            id_terbaru = cur.lastrowid
            conn.commit()
            sudah_commit = True

            if stok > 0:
                catat_restock_aman(id_terbaru, stok, harga_beli)

            catat_audit(
                "TAMBAH_PRODUK",
                f"Menambah '{nama}' (ID #{id_terbaru}, stok: {stok}, jual: {harga_jual})"
            )

        return jsonify({
            "ok": True,
            "id_terbaru": id_terbaru,
            "pesan": f"Produk '{nama}' berhasil disimpan"
        })
    except ValueError as e:
        conn.rollback()
        # Foto baru hanya dihapus kalau produk BELUM tersimpan (belum commit)
        if foto_baru_tersimpan and not sudah_commit:
            hapus_file_foto(foto_baru_tersimpan)
        return jsonify({"ok": False, "pesan": str(e)}), 400
    except Exception:
        conn.rollback()
        if foto_baru_tersimpan and not sudah_commit:
            hapus_file_foto(foto_baru_tersimpan)
        app.logger.exception("Gagal menyimpan produk")
        return jsonify({"ok": False, "pesan": "Terjadi kesalahan saat menyimpan produk."}), 500


@app.route("/api/produk/<int:produk_id>", methods=["DELETE"])
@login_required
@admin_required
def api_hapus_produk(produk_id):
    conn = db.get_connection()
    try:
        row = conn.execute("SELECT nama, gambar FROM produk WHERE id = ?", (produk_id,)).fetchone()
        if not row:
            return jsonify({"ok": False, "pesan": "Produk tidak ditemukan"}), 404

        nama_produk = row["nama"]
        gambar_produk = row["gambar"]

        conn.execute("DELETE FROM produk WHERE id = ?", (produk_id,))
        conn.commit()

        if gambar_produk:
            path_foto = os.path.join(FOLDER_IMG, os.path.basename(gambar_produk))
            if os.path.exists(path_foto):
                try:
                    os.remove(path_foto)
                except OSError:
                    pass

        catat_audit("HAPUS_PRODUK", f"Menghapus produk '{nama_produk}' (ID #{produk_id})")
        return jsonify({"ok": True})
    except Exception:
        conn.rollback()
        app.logger.exception("Gagal menghapus produk")
        return jsonify({"ok": False, "pesan": "Terjadi kesalahan saat menghapus produk."}), 500


# ==================== API KELOLA KATEGORI ====================

@app.route("/api/kategori", methods=["POST"])
@login_required
@admin_required
def api_tambah_kategori():
    data = request.get_json(silent=True) or {}
    nama = data.get("nama", "").strip()
    if not nama or len(nama) > 60:
        return jsonify({"ok": False, "pesan": "Nama kategori wajib diisi (maksimal 60 karakter)"}), 400
    conn = db.get_connection()
    conn.execute("INSERT OR IGNORE INTO kategori (nama) VALUES (?)", (nama,))
    conn.commit()
    catat_audit("KELOLA_KATEGORI", f"Menambah kategori '{nama}'")
    return jsonify({"ok": True})


@app.route("/api/kategori/<int:kat_id>", methods=["PUT"])
@login_required
@admin_required
def api_edit_kategori(kat_id):
    data = request.get_json(silent=True) or {}
    nama_baru = data.get("nama", "").strip()
    if not nama_baru or len(nama_baru) > 60:
        return jsonify({"ok": False, "pesan": "Nama kategori wajib diisi (maksimal 60 karakter)"}), 400
    conn = db.get_connection()
    lama = conn.execute("SELECT nama FROM kategori WHERE id = ?", (kat_id,)).fetchone()
    if lama:
        try:
            conn.execute("UPDATE kategori SET nama = ? WHERE id = ?", (nama_baru, kat_id))
            conn.execute("UPDATE produk SET kategori = ? WHERE kategori = ?", (nama_baru, lama["nama"]))
            conn.commit()
            catat_audit("KELOLA_KATEGORI", f"Mengubah kategori '{lama['nama']}' → '{nama_baru}'")
        except sqlite3.IntegrityError:
            conn.rollback()
            return jsonify({"ok": False, "pesan": f"Kategori '{nama_baru}' sudah ada"}), 400
    return jsonify({"ok": True})


@app.route("/api/kategori/<int:kat_id>", methods=["DELETE"])
@login_required
@admin_required
def api_hapus_kategori(kat_id):
    conn = db.get_connection()
    lama = conn.execute("SELECT nama FROM kategori WHERE id = ?", (kat_id,)).fetchone()
    conn.execute("DELETE FROM kategori WHERE id = ?", (kat_id,))
    conn.commit()
    if lama:
        catat_audit("KELOLA_KATEGORI", f"Menghapus kategori '{lama['nama']}'")
    return jsonify({"ok": True})


# ==================== API RIWAYAT BARANG MASUK (KULAKAN) ====================

@app.route("/api/barang_masuk", methods=["GET"])
@login_required
@admin_required
def api_barang_masuk():
    conn = db.get_connection()
    rows = conn.execute("""
        SELECT bm.id, bm.tanggal, bm.jumlah, bm.harga_beli,
               COALESCE(p.nama, 'Produk Dihapus') AS nama_produk,
               COALESCE(p.satuan, 'pcs') AS satuan
        FROM barang_masuk bm
        LEFT JOIN produk p ON bm.produk_id = p.id
        ORDER BY bm.id DESC LIMIT 100
    """).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


# ==================== API KASIR & TRANSAKSI ====================

@app.route("/api/transaksi", methods=["POST"])
@login_required
def api_buat_transaksi():
    data = request.get_json(silent=True) or {}
    items = data.get("items", [])

    if not isinstance(items, list) or not items:
        return jsonify({"ok": False, "pesan": "Keranjang masih kosong"}), 400

    try:
        bayar = int(float(data.get("bayar", 0) or 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "pesan": "Nominal pembayaran tidak valid"}), 400

    if bayar < 0:
        return jsonify({"ok": False, "pesan": "Nominal pembayaran tidak boleh negatif"}), 400

    # Validasi jumlah >= 1 dan gabungkan jika ada produk_id ganda dalam satu request
    qty_per_produk = {}
    for item in items:
        try:
            pid = int(item.get("produk_id", 0))
            qty = int(item.get("jumlah", 0))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "pesan": "Data item keranjang tidak valid"}), 400

        if pid <= 0 or qty < 1:
            return jsonify({"ok": False, "pesan": "Jumlah pembelian tiap barang minimal 1"}), 400

        qty_per_produk[pid] = qty_per_produk.get(pid, 0) + qty

    conn = db.get_connection()
    try:
        cur = conn.cursor()
        if not conn.in_transaction:
            cur.execute("BEGIN IMMEDIATE")
        tanggal = sekarang_wib().strftime("%Y-%m-%d %H:%M:%S")

        total_belanja = 0
        total_profit = 0
        detail_siap = []

        for pid, qty in qty_per_produk.items():
            prod = cur.execute("SELECT * FROM produk WHERE id = ?", (pid,)).fetchone()
            if not prod:
                conn.rollback()
                return jsonify({"ok": False, "pesan": f"Produk ID {pid} tidak ditemukan"}), 400
            if prod["stok"] < qty:
                conn.rollback()
                return jsonify({"ok": False, "pesan": f"Stok '{prod['nama']}' tidak mencukupi (sisa {prod['stok']})"}), 400

            harga_beli = float(prod["harga_beli"] or 0)
            harga_jual = float(prod["harga_jual"] or 0)
            subtotal = harga_jual * qty
            profit_item = (harga_jual - harga_beli) * qty

            total_belanja += subtotal
            total_profit += profit_item
            detail_siap.append({
                "produk_id": pid,
                "nama_produk": prod["nama"],
                "harga_beli": harga_beli,
                "harga_satuan": harga_jual,
                "jumlah": qty,
                "subtotal": subtotal
            })

        if bayar < total_belanja:
            conn.rollback()
            return jsonify({
                "ok": False,
                "pesan": f"Uang pembayaran kurang! Total saat ini {utils.format_rupiah(total_belanja)}."
            }), 400

        kembalian = bayar - total_belanja
        trx_cols = get_table_columns("transaksi")

        kolom_insert = ["tanggal"]
        nilai_insert = [tanggal]

        if "total" in trx_cols:
            kolom_insert.append("total")
            nilai_insert.append(total_belanja)
        if "total_harga" in trx_cols:
            kolom_insert.append("total_harga")
            nilai_insert.append(total_belanja)
        if "bayar" in trx_cols:
            kolom_insert.append("bayar")
            nilai_insert.append(bayar)
        if "dibayar" in trx_cols:
            kolom_insert.append("dibayar")
            nilai_insert.append(bayar)
        if "kembalian" in trx_cols:
            kolom_insert.append("kembalian")
            nilai_insert.append(kembalian)
        if "keuntungan" in trx_cols:
            kolom_insert.append("keuntungan")
            nilai_insert.append(total_profit)
        if "status" in trx_cols:
            kolom_insert.append("status")
            nilai_insert.append("selesai")

        placeholders = ", ".join(["?"] * len(kolom_insert))
        cur.execute(
            f"INSERT INTO transaksi ({', '.join(kolom_insert)}) VALUES ({placeholders})",
            nilai_insert
        )

        trx_id = cur.lastrowid

        for d in detail_siap:
            cur.execute("""
                INSERT INTO transaksi_detail
                (transaksi_id, produk_id, nama_produk, harga_beli, harga_satuan, jumlah, subtotal)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                trx_id, d["produk_id"], d["nama_produk"],
                d["harga_beli"], d["harga_satuan"], d["jumlah"], d["subtotal"]
            ))
            cur.execute(
                "UPDATE produk SET stok = stok - ? WHERE id = ? AND stok >= ?",
                (d["jumlah"], d["produk_id"], d["jumlah"])
            )
            if cur.rowcount == 0:
                conn.rollback()
                return jsonify({
                    "ok": False,
                    "pesan": f"Stok '{d['nama_produk']}' baru saja habis atau berubah!"
                }), 409

        conn.commit()

        return jsonify({
            "ok": True,
            "struk": {
                "id": trx_id,
                "tanggal": tanggal,
                "kasir": session.get("username", "kasir"),
                "items": [
                    {
                        "nama_produk": d["nama_produk"],
                        "jumlah": d["jumlah"],
                        "harga_satuan": d["harga_satuan"],
                        "subtotal": d["subtotal"],
                    }
                    for d in detail_siap  # harga_beli sengaja tidak dikirim ke browser
                ],
                "total": total_belanja,
                "bayar": bayar,
                "kembalian": kembalian
            }
        })
    except Exception:
        conn.rollback()
        app.logger.exception("Gagal memproses transaksi")
        return jsonify({"ok": False, "pesan": "Terjadi kesalahan saat memproses transaksi. Silakan coba lagi."}), 500


# ==================== API RIWAYAT & RETUR (KHUSUS ADMIN) ====================

@app.route("/api/riwayat", methods=["GET"])
@login_required
@admin_required
def api_riwayat():
    conn = db.get_connection()
    periode = request.args.get("periode", "hari_ini")
    now = sekarang_wib()

    where_sql = "1=1"
    params = []

    if periode == "hari_ini":
        where_sql = "DATE(tanggal) = ?"
        params.append(now.strftime("%Y-%m-%d"))
    elif periode == "7_hari":
        batas = (now - timedelta(days=7)).strftime("%Y-%m-%d 00:00:00")
        where_sql = "tanggal >= ?"
        params.append(batas)
    elif periode == "bulan_ini":
        where_sql = "strftime('%Y-%m', tanggal) = ?"
        params.append(now.strftime("%Y-%m"))

    rows = conn.execute(
        f"SELECT * FROM transaksi WHERE {where_sql} ORDER BY id DESC",
        params
    ).fetchall()

    transaksi_list = []
    total_omzet = 0
    total_profit = 0
    jumlah_aktif = 0

    for r in rows:
        d = dict(r)
        is_retur = (d.get("status") == "retur")
        nom_total = float(d.get("total", d.get("total_harga", 0)) or 0)
        nom_profit = d.get("keuntungan")

        if nom_profit is None:
            prof_row = conn.execute("""
                SELECT COALESCE(SUM((harga_satuan - harga_beli) * jumlah), 0) AS prof
                FROM transaksi_detail WHERE transaksi_id = ?
            """, (d["id"],)).fetchone()
            nom_profit = float(prof_row["prof"] if prof_row else 0)
        else:
            nom_profit = float(nom_profit or 0)

        d["status"] = "retur" if is_retur else "selesai"
        d["total_tampil"] = nom_total
        d["profit_tampil"] = nom_profit
        if not is_retur:
            total_omzet += nom_total
            total_profit += nom_profit
            jumlah_aktif += 1
        transaksi_list.append(d)

    return jsonify({
        "transaksi": transaksi_list,
        "total_omzet": total_omzet,
        "total_profit": total_profit,
        "jumlah_trx": jumlah_aktif
    })


@app.route("/api/riwayat/<int:trx_id>", methods=["GET"])
@login_required
@admin_required
def api_detail_transaksi(trx_id):
    conn = db.get_connection()
    trx = conn.execute("SELECT * FROM transaksi WHERE id = ?", (trx_id,)).fetchone()
    if not trx:
        return jsonify({"ok": False, "pesan": "Transaksi tidak ditemukan"}), 404

    items = conn.execute(
        "SELECT * FROM transaksi_detail WHERE transaksi_id = ?",
        (trx_id,)
    ).fetchall()

    t_dict = dict(trx)
    return jsonify({
        "ok": True,
        "struk": {
            "id": t_dict["id"],
            "tanggal": t_dict.get("tanggal", ""),
            "total": t_dict.get("total", t_dict.get("total_harga", 0)),
            "bayar": t_dict.get("bayar") or t_dict.get("dibayar", 0),
            "kembalian": t_dict.get("kembalian", 0),
            "items": [dict(i) for i in items]
        }
    })


@app.route("/api/riwayat/<int:trx_id>/retur", methods=["POST"])
@login_required
@admin_required
def api_retur_transaksi(trx_id):
    """Membatalkan transaksi (soft-delete) dan mengembalikan stok produk."""
    conn = db.get_connection()
    try:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")

        trx = conn.execute("SELECT * FROM transaksi WHERE id = ?", (trx_id,)).fetchone()
        if not trx:
            conn.rollback()
            return jsonify({"ok": False, "pesan": "Transaksi tidak ditemukan"}), 404

        trx_dict = dict(trx)
        if trx_dict.get("status") == "retur":
            conn.rollback()
            return jsonify({"ok": False, "pesan": "Transaksi ini sudah dibatalkan sebelumnya"}), 400

        nominal = float(trx_dict.get("total", trx_dict.get("total_harga", 0)) or 0)
        items = conn.execute(
            "SELECT produk_id, jumlah FROM transaksi_detail WHERE transaksi_id = ?",
            (trx_id,)
        ).fetchall()

        for item in items:
            conn.execute(
                "UPDATE produk SET stok = stok + ? WHERE id = ?",
                (item["jumlah"], item["produk_id"])
            )

        conn.execute("UPDATE transaksi SET status = 'retur' WHERE id = ?", (trx_id,))
        conn.commit()

        catat_audit("RETUR_TRANSAKSI", f"Membatalkan transaksi #{trx_id} (Rp {int(nominal):,})")
        return jsonify({"ok": True, "pesan": f"Transaksi #{trx_id} dibatalkan & stok dikembalikan"})
    except Exception:
        conn.rollback()
        app.logger.exception("Gagal membatalkan transaksi")
        return jsonify({"ok": False, "pesan": "Terjadi kesalahan saat membatalkan transaksi."}), 500


@app.route("/api/audit_log", methods=["GET"])
@login_required
@admin_required
def api_audit_log():
    conn = db.get_connection()
    rows = conn.execute(
        "SELECT id, tanggal, username, aksi, detail FROM audit_log ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return jsonify({"logs": [dict(r) for r in rows]})


# ==================== API DASHBOARD ANALITIK (KHUSUS ADMIN) ====================

@app.route("/api/dashboard", methods=["GET"])
@login_required
@admin_required
def api_dashboard():
    conn = db.get_connection()
    now = sekarang_wib()
    hari_ini = now.strftime("%Y-%m-%d")
    kemarin = (now - timedelta(days=1)).strftime("%Y-%m-%d")
    bulan_ini = now.strftime("%Y-%m")

    trx_cols = get_table_columns("transaksi")
    col_total = "total" if "total" in trx_cols else "total_harga"

    row_today = conn.execute(f"""
        SELECT COALESCE(SUM({col_total}), 0) AS omzet, COUNT(*) AS jml
        FROM transaksi
        WHERE DATE(tanggal) = ?
          AND COALESCE(status, 'selesai') != 'retur'
    """, (hari_ini,)).fetchone()

    row_yesterday = conn.execute(f"""
        SELECT COALESCE(SUM({col_total}), 0) AS omzet
        FROM transaksi
        WHERE DATE(tanggal) = ?
          AND COALESCE(status, 'selesai') != 'retur'
    """, (kemarin,)).fetchone()

    profit_today_row = conn.execute("""
        SELECT COALESCE(SUM((td.harga_satuan - td.harga_beli) * td.jumlah), 0) AS profit
        FROM transaksi_detail td
        JOIN transaksi t ON td.transaksi_id = t.id
        WHERE DATE(t.tanggal) = ?
          AND COALESCE(t.status, 'selesai') != 'retur'
    """, (hari_ini,)).fetchone()

    top_produk = conn.execute("""
        SELECT td.nama_produk, SUM(td.jumlah) AS total_qty
        FROM transaksi_detail td
        JOIN transaksi t ON td.transaksi_id = t.id
        WHERE strftime('%Y-%m', t.tanggal) = ?
          AND COALESCE(t.status, 'selesai') != 'retur'
        GROUP BY td.produk_id, td.nama_produk
        ORDER BY total_qty DESC LIMIT 5
    """, (bulan_ini,)).fetchall()

    top_profit = conn.execute("""
        SELECT td.nama_produk,
               SUM((td.harga_satuan - td.harga_beli) * td.jumlah) AS total_profit
        FROM transaksi_detail td
        JOIN transaksi t ON td.transaksi_id = t.id
        WHERE strftime('%Y-%m', t.tanggal) = ?
          AND COALESCE(t.status, 'selesai') != 'retur'
        GROUP BY td.produk_id, td.nama_produk
        ORDER BY total_profit DESC LIMIT 5
    """, (bulan_ini,)).fetchall()

    top_kategori = conn.execute("""
        SELECT COALESCE(NULLIF(p.kategori, ''), 'Tanpa Kategori') AS kategori,
               SUM((td.harga_satuan - td.harga_beli) * td.jumlah) AS total_profit,
               SUM(td.jumlah) AS total_qty
        FROM transaksi_detail td
        JOIN transaksi t ON td.transaksi_id = t.id
        LEFT JOIN produk p ON td.produk_id = p.id
        WHERE strftime('%Y-%m', t.tanggal) = ?
          AND COALESCE(t.status, 'selesai') != 'retur'
        GROUP BY kategori
        ORDER BY total_profit DESC LIMIT 5
    """, (bulan_ini,)).fetchall()

    stok_menipis = conn.execute("SELECT COUNT(*) AS c FROM produk WHERE stok <= 5").fetchone()["c"]
    batas_exp = (now + timedelta(days=90)).strftime("%Y-%m-%d")
    hampir_exp = conn.execute("""
        SELECT COUNT(*) AS c FROM produk
        WHERE expired_date IS NOT NULL AND expired_date != '' AND expired_date <= ?
    """, (batas_exp,)).fetchone()["c"]

    return jsonify({
        "omzet_hari_ini": float(row_today["omzet"] or 0),
        "omzet_kemarin": float(row_yesterday["omzet"] or 0),
        "profit_hari_ini": float(profit_today_row["profit"] or 0),
        "trx_hari_ini": int(row_today["jml"] or 0),
        "top_produk": [dict(r) for r in top_produk],
        "top_profit": [dict(r) for r in top_profit],
        "top_kategori": [dict(r) for r in top_kategori],
        "stok_menipis": stok_menipis,
        "hampir_exp": hampir_exp
    })

# ==================== API KEAMANAN: UBAH PIN (KHUSUS ADMIN) ====================


@app.route("/api/ubah_pin", methods=["POST"])
@login_required
@admin_required
def api_ubah_pin():
    ip = get_client_ip()
    admin_aktif = session.get("username", "admin")

    terkunci, sisa_detik = _cek_blokir_ubah_pin(ip, admin_aktif)
    if terkunci:
        return jsonify({
            "ok": False,
            "pesan": f"Terlalu banyak percobaan ubah PIN gagal. Coba lagi dalam {format_sisa_waktu(sisa_detik)}."
        }), 429

    data = request.get_json(silent=True) or {}
    target_user = data.get("target_user", "").strip().lower()
    pin_admin_lama = str(data.get("pin_admin_lama", "")).strip()
    pin_baru = str(data.get("pin_baru", "")).strip()
    pin_konfirmasi = str(data.get("pin_konfirmasi", "")).strip()

    if target_user not in ("admin", "kasir"):
        return jsonify({"ok": False, "pesan": "Akun tujuan tidak valid"}), 400

    if not pin_baru.isdigit() or not (4 <= len(pin_baru) <= 6):
        return jsonify({"ok": False, "pesan": "PIN baru harus berupa 4 sampai 6 digit angka"}), 400

    if pin_baru in PIN_BAWAAN.values():
        return jsonify({"ok": False, "pesan": "Jangan gunakan PIN bawaan (1234 atau 0000)"}), 400

    if pin_baru != pin_konfirmasi:
        return jsonify({"ok": False, "pesan": "Konfirmasi PIN baru tidak cocok"}), 400

    conn = db.get_connection()
    admin_row = conn.execute("SELECT pin FROM users WHERE username = 'admin'").fetchone()
    if not admin_row or not verifikasi_pin_db(admin_row["pin"], pin_admin_lama):
        time.sleep(0.5)
        jml_gagal = _catat_gagal_ubah_pin(ip, admin_aktif, target_user)
        terkunci_sekarang, sisa_kunci = _cek_blokir_ubah_pin(ip, admin_aktif)
        if terkunci_sekarang:
            return jsonify({
                "ok": False,
                "pesan": f"Terlalu banyak percobaan salah. Fitur ubah PIN dikunci {format_sisa_waktu(sisa_kunci)}."
            }), 429
        return jsonify({"ok": False, "pesan": f"PIN Admin saat ini salah! Sisa percobaan: {BATAS_GAGAL_LOGIN - jml_gagal} kali."}), 403

    _reset_gagal_ubah_pin(ip, admin_aktif)

    pin_baru_hash = generate_password_hash(pin_baru)
    conn.execute(
        "UPDATE users SET pin = ?, wajib_ganti_pin = 0, session_version = COALESCE(session_version, 1) + 1 WHERE username = ?",
        (pin_baru_hash, target_user)
    )
    conn.commit()

    if target_user == session.get("username"):
        row_sv = conn.execute(
            "SELECT COALESCE(session_version, 1) AS sv FROM users WHERE username = ?",
            (target_user,)
        ).fetchone()
        session["session_version"] = int(row_sv["sv"]) if row_sv else 1

    catat_audit("UBAH_PIN", f"Mengubah PIN untuk akun '{target_user}'")

    return jsonify({
        "ok": True,
        "pesan": f"PIN untuk akun '{target_user}' berhasil diperbarui!",
        "pin_status": cek_status_pin_default()
    })

# ==================== API KEAMANAN: BACKUP DATABASE & FOTO ====================

@app.route("/api/backup/db", methods=["GET"])
@login_required
@admin_required
def api_backup_db():
    """Membuat snapshot atomik database SQLite dan mengunduhnya sebagai file .db."""
    timestamp = sekarang_wib().strftime("%Y%m%d_%H%M")
    fd, temp_db = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    try:
        src_conn = db.get_connection()
        dst_conn = sqlite3.connect(temp_db)
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()

        @after_this_request
        def hapus_temp_db(response):
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except OSError:
                    pass
            return response

        catat_audit("UNDUH_BACKUP", f"Mengunduh backup database (petshop_backup_{timestamp}.db)")

        return send_file(
            temp_db,
            mimetype="application/x-sqlite3",
            as_attachment=True,
            download_name=f"petshop_backup_{timestamp}.db"
        )
    except Exception:
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except OSError:
                pass
        app.logger.exception("Gagal membuat backup database")
        return jsonify({"ok": False, "pesan": "Gagal membuat cadangan database."}), 500


@app.route("/api/backup/full", methods=["GET"])
@login_required
@admin_required
def api_backup_full():
    """Mengemas snapshot database dan seluruh folder img_produk menjadi satu file .zip."""
    timestamp = sekarang_wib().strftime("%Y%m%d_%H%M")
    fd, temp_db = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    try:
        src_conn = db.get_connection()
        dst_conn = sqlite3.connect(temp_db)
        src_conn.backup(dst_conn)
        dst_conn.close()

        mem_zip = io.BytesIO()
        with zipfile.ZipFile(mem_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(temp_db, arcname="petshop.db")
            if os.path.exists(FOLDER_IMG):
                for nama_file in os.listdir(FOLDER_IMG):
                    full_path = os.path.join(FOLDER_IMG, nama_file)
                    if os.path.isfile(full_path):
                        zf.write(full_path, arcname=os.path.join("img_produk", nama_file))

        mem_zip.seek(0)
        catat_audit("UNDUH_BACKUP", f"Mengunduh backup lengkap ZIP (Backup_Petshop_Lengkap_{timestamp}.zip)")

        return send_file(
            mem_zip,
            mimetype="application/zip",
            as_attachment=True,
            download_name=f"Backup_Petshop_Lengkap_{timestamp}.zip"
        )
    finally:
        if os.path.exists(temp_db):
            try:
                os.remove(temp_db)
            except OSError:
                pass

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)