import io
import os
import time
import sqlite3
import zipfile
import tempfile
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify,
    send_from_directory, send_file, after_this_request,
    session, redirect, url_for
)
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps, UnidentifiedImageError
import db
import utils

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


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


@app.before_request
def validasi_sesi_dan_csrf():
    # 1. Cek keaslian sesi aktif via session_version (hanguskan jika akun dihapus atau PIN diganti)
    if request.endpoint not in ("static", "login") and "username" in session:
        conn = db.get_connection()
        user = conn.execute(
            "SELECT role, COALESCE(session_version, 1) AS session_version FROM users WHERE username = ?",
            (session["username"],)
        ).fetchone()

        if not user or user["session_version"] != session.get("session_version"):
            session.clear()
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "pesan": "Sesi berakhir karena PIN telah diperbarui. Silakan login ulang."}), 401
            return redirect(url_for("login"))

        session["role"] = user["role"]

    # 2. Validasi CSRF untuk semua request pengubah data (termasuk POST /logout)
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
BATAS_GAGAL_LOGIN = 5
DURASI_BLOKIR_DETIK = 300  # 5 menit
PERCOBAAN_LOGIN_GAGAL = {}


def get_client_ip():
    """Mengambil IP pengunjung secara aman dari reverse proxy."""
    real_ip = request.headers.get("X-Real-IP", "").strip()
    if real_ip:
        return real_ip
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # Ambil IP paling kanan yang ditambahkan oleh reverse proxy terpercaya
        return forwarded.split(",")[-1].strip()
    return request.remote_addr or "unknown"


def format_sisa_waktu(detik):
    menit, sisa_detik = divmod(max(1, int(detik)), 60)
    if menit > 0:
        return f"{menit} menit {sisa_detik} detik"
    return f"{sisa_detik} detik"


def _kunci_pelacak(ip, username=""):
    kunci = [f"ip:{ip}"]
    if username:
        kunci.append(f"user:{username.lower()}")
    return kunci


def cek_status_blokir_login(ip, username=""):
    """Mengecek apakah IP atau akun target sedang diblokir sementara."""
    sekarang = time.time()
    sisa_terlama = 0

    for k in _kunci_pelacak(ip, username):
        data = PERCOBAAN_LOGIN_GAGAL.get(k)
        if not data:
            continue
        locked_until = data.get("locked_until", 0)
        if locked_until > sekarang:
            sisa_terlama = max(sisa_terlama, int(locked_until - sekarang))
        elif locked_until > 0:
            PERCOBAAN_LOGIN_GAGAL.pop(k, None)

    return (sisa_terlama > 0), sisa_terlama


def catat_kegagalan_login(ip, username=""):
    """Mencatat kegagalan login per IP dan per akun target."""
    sekarang = time.time()

    if len(PERCOBAAN_LOGIN_GAGAL) > 500:
        expired_keys = [
            k for k, v in PERCOBAAN_LOGIN_GAGAL.items()
            if v.get("locked_until", 0) < sekarang and (sekarang - v.get("last_try", 0)) > 900
        ]
        for k in expired_keys:
            PERCOBAAN_LOGIN_GAGAL.pop(k, None)

    max_count = 0
    baru_terkunci = False

    for k in _kunci_pelacak(ip, username):
        data = PERCOBAAN_LOGIN_GAGAL.get(k, {"count": 0, "locked_until": 0, "last_try": sekarang})
        data["count"] += 1
        data["last_try"] = sekarang

        if data["count"] >= BATAS_GAGAL_LOGIN and data.get("locked_until", 0) <= sekarang:
            data["locked_until"] = sekarang + DURASI_BLOKIR_DETIK
            baru_terkunci = True

        PERCOBAAN_LOGIN_GAGAL[k] = data
        max_count = max(max_count, data["count"])

    if baru_terkunci:
        catat_audit(
            "LOGIN_TERKUNCI",
            f"Terblokir sementara setelah {BATAS_GAGAL_LOGIN}x gagal (IP: {ip})",
            username=username or "unknown"
        )

    return max_count


def reset_kegagalan_login(ip, username=""):
    for k in _kunci_pelacak(ip, username):
        PERCOBAAN_LOGIN_GAGAL.pop(k, None)

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
migrasi_hash_pin()

def catat_audit(aksi, detail="", username=None):
    """Mencatat aktivitas sensitif ke tabel audit_log."""
    user_aktif = username or session.get("username") or "system"
    waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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


def catat_restock(produk_id, jumlah, harga_beli):
    if jumlah <= 0:
        return
    conn = db.get_connection()
    tanggal = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
            sisa_coba = BATAS_GAGAL_LOGIN - jumlah_gagal

            if sisa_coba <= 0:
                error = f"Terlalu banyak percobaan gagal. Akun dikunci selama {format_sisa_waktu(DURASI_BLOKIR_DETIK)}."
                return render_template(
                    "login.html",
                    error=error,
                    sisa_detik=DURASI_BLOKIR_DETIK,
                    username=username
                ), 429
            else:
                error = f"Username atau PIN salah! Sisa percobaan: {sisa_coba} kali."

    return render_template("login.html", error=error, sisa_detik=0, username=username_form)


@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("username")
    if username:
        catat_audit("LOGOUT", "Keluar dari sistem", username=username)
    session.clear()
    return jsonify({"ok": True, "redirect": url_for("login")})

def cek_status_pin_default():
    conn = db.get_connection()
    admin_row = conn.execute("SELECT pin FROM users WHERE username = 'admin'").fetchone()
    kasir_row = conn.execute("SELECT pin FROM users WHERE username = 'kasir'").fetchone()
    return {
        "admin_default": bool(admin_row and verifikasi_pin_db(admin_row["pin"], "1234")),
        "kasir_default": bool(kasir_row and verifikasi_pin_db(kasir_row["pin"], "0000")),
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
        batas_exp = (datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d")
        where_clauses.append("p.expired_date IS NOT NULL AND p.expired_date != '' AND p.expired_date <= ?")
        params.append(batas_exp)
    elif filter_khusus == "dead_stock":
        batas_30 = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
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

            if foto_baru_tersimpan and foto_lama_db:
                hapus_file_foto(foto_lama_db)

            if stok > stok_lama:
                catat_restock(pid, stok - stok_lama, harga_beli)

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

            if stok > 0:
                catat_restock(id_terbaru, stok, harga_beli)

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
        if foto_baru_tersimpan:
            hapus_file_foto(foto_baru_tersimpan)
        return jsonify({"ok": False, "pesan": str(e)}), 400
    except Exception:
        conn.rollback()
        if foto_baru_tersimpan:
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
        tanggal = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
                "items": detail_siap,
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
    now = datetime.now()

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
    now = datetime.now()
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
PERCOBAAN_UBAH_PIN_GAGAL = {}


def _cek_blokir_ubah_pin(ip, username):
    sekarang = time.time()
    sisa_terlama = 0
    for k in (f"pin_ip:{ip}", f"pin_user:{username}"):
        data = PERCOBAAN_UBAH_PIN_GAGAL.get(k)
        if not data:
            continue
        locked_until = data.get("locked_until", 0)
        if locked_until > sekarang:
            sisa_terlama = max(sisa_terlama, int(locked_until - sekarang))
        elif locked_until > 0:
            PERCOBAAN_UBAH_PIN_GAGAL.pop(k, None)
    return (sisa_terlama > 0), sisa_terlama


def _catat_gagal_ubah_pin(ip, username, target_user):
    sekarang = time.time()
    max_count = 0
    baru_terkunci = False

    for k in (f"pin_ip:{ip}", f"pin_user:{username}"):
        data = PERCOBAAN_UBAH_PIN_GAGAL.get(k, {"count": 0, "locked_until": 0, "last_try": sekarang})
        data["count"] += 1
        data["last_try"] = sekarang
        if data["count"] >= BATAS_GAGAL_LOGIN and data.get("locked_until", 0) <= sekarang:
            data["locked_until"] = sekarang + DURASI_BLOKIR_DETIK
            baru_terkunci = True
        PERCOBAAN_UBAH_PIN_GAGAL[k] = data
        max_count = max(max_count, data["count"])

    catat_audit(
        "UBAH_PIN_GAGAL",
        f"PIN Admin lama salah saat mengubah PIN '{target_user}' (IP: {ip})",
        username=username
    )
    if baru_terkunci:
        catat_audit(
            "UBAH_PIN_TERKUNCI",
            f"Fitur ubah PIN dikunci sementara setelah {BATAS_GAGAL_LOGIN}x gagal (IP: {ip})",
            username=username
        )
    return max_count


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

    if pin_baru in ("1234", "0000"):
        return jsonify({"ok": False, "pesan": "Jangan gunakan PIN bawaan (1234 atau 0000)"}), 400

    if pin_baru != pin_konfirmasi:
        return jsonify({"ok": False, "pesan": "Konfirmasi PIN baru tidak cocok"}), 400

    conn = db.get_connection()
    admin_row = conn.execute("SELECT pin FROM users WHERE username = 'admin'").fetchone()
    if not admin_row or not verifikasi_pin_db(admin_row["pin"], pin_admin_lama):
        time.sleep(0.5)
        jml_gagal = _catat_gagal_ubah_pin(ip, admin_aktif, target_user)
        sisa_coba = BATAS_GAGAL_LOGIN - jml_gagal
        if sisa_coba <= 0:
            return jsonify({
                "ok": False,
                "pesan": f"Terlalu banyak percobaan salah. Fitur ubah PIN dikunci {format_sisa_waktu(DURASI_BLOKIR_DETIK)}."
            }), 429
        return jsonify({"ok": False, "pesan": f"PIN Admin saat ini salah! Sisa percobaan: {sisa_coba} kali."}), 403

    for k in (f"pin_ip:{ip}", f"pin_user:{admin_aktif}"):
        PERCOBAAN_UBAH_PIN_GAGAL.pop(k, None)

    pin_baru_hash = generate_password_hash(pin_baru)
    conn.execute(
        "UPDATE users SET pin = ?, session_version = COALESCE(session_version, 1) + 1 WHERE username = ?",
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
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
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
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
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