import os
import time
import inspect
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, jsonify,
    send_from_directory, session, redirect, url_for
)
from PIL import Image, ImageOps
import db

app = Flask(__name__)
app.secret_key = "petshop-kunci-rahasia-aman-2026"
app.permanent_session_lifetime = timedelta(days=30)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FOLDER_IMG = os.path.join(BASE_DIR, "img_produk")
os.makedirs(FOLDER_IMG, exist_ok=True)

if hasattr(db, "init_db"):
    db.init_db()


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
        cur.execute("INSERT INTO users (username, pin, role) VALUES ('admin', '1234', 'admin')")
        cur.execute("INSERT INTO users (username, pin, role) VALUES ('kasir', '0000', 'kasir')")

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

    conn.commit()


inisialisasi_skema_lengkap()


def get_table_columns(table_name):
    conn = db.get_connection()
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return [r["name"] for r in rows]


def cek_kredensial(username, pin):
    if hasattr(db, "verifikasi_login"):
        return db.verifikasi_login(username, pin)
    conn = db.get_connection()
    user = conn.execute(
        "SELECT role FROM users WHERE username = ? AND pin = ?",
        (username, pin)
    ).fetchone()
    return user["role"] if user else None


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


def proses_dan_kompres_foto(file_storage, foto_lama=""):
    if not file_storage or not file_storage.filename:
        return foto_lama

    ekstensi = os.path.splitext(file_storage.filename)[1].lower()
    if ekstensi not in (".jpg", ".jpeg", ".png", ".webp"):
        return foto_lama

    nama_file_baru = f"prod_{int(time.time() * 1000)}.jpg"
    path_simpan = os.path.join(FOLDER_IMG, nama_file_baru)

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
        img.save(path_simpan, "JPEG", optimize=True, quality=80)

    if foto_lama and foto_lama != nama_file_baru:
        path_lama = os.path.join(FOLDER_IMG, foto_lama)
        if os.path.exists(path_lama):
            try:
                os.remove(path_lama)
            except OSError:
                pass

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

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        pin = request.form.get("pin", "").strip()
        role = cek_kredensial(username, pin)

        if role:
            session.permanent = True
            session["username"] = username
            session["role"] = role
            return redirect(url_for("index"))
        else:
            error = "Username atau PIN salah!"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        role=session.get("role", "kasir"),
        username=session.get("username", "kasir")
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
    page = max(1, int(request.args.get("page", 1) or 1))
    limit = int(request.args.get("limit", 0) or 0)

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
            p.id NOT IN (
                SELECT DISTINCT td.produk_id
                FROM transaksi_detail td
                JOIN transaksi t ON td.transaksi_id = t.id
                WHERE t.tanggal >= ?
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


@app.route("/api/produk", methods=["POST"])
@login_required
@admin_required
def api_simpan_produk():
    try:
        conn = db.get_connection()
        produk_id = request.form.get("id", "").strip()
        nama = request.form.get("nama", "").strip()
        kategori = request.form.get("kategori", "").strip()
        harga_beli = int(float(request.form.get("harga_beli", 0) or 0))
        harga_jual = int(float(request.form.get("harga_jual", 0) or 0))
        stok = int(float(request.form.get("stok", 0) or 0))
        satuan = request.form.get("satuan", "pcs").strip() or "pcs"
        expired_date = request.form.get("expired_date", "").strip()
        foto_lama = request.form.get("gambar_lama", "").strip()

        if not nama:
            return jsonify({"ok": False, "pesan": "Nama produk wajib diisi"}), 400

        if kategori:
            conn.execute("INSERT OR IGNORE INTO kategori (nama) VALUES (?)", (kategori,))

        file_foto = request.files.get("gambar")
        nama_gambar = proses_dan_kompres_foto(file_foto, foto_lama)

        if produk_id:
            pid = int(produk_id)
            lama = conn.execute("SELECT stok FROM produk WHERE id = ?", (pid,)).fetchone()
            stok_lama = lama["stok"] if lama else 0

            conn.execute("""
                UPDATE produk
                SET nama=?, kategori=?, harga_beli=?, harga_jual=?, stok=?, satuan=?, gambar=?, expired_date=?
                WHERE id=?
            """, (nama, kategori, harga_beli, harga_jual, stok, satuan, nama_gambar, expired_date, pid))
            conn.commit()

            # Smart Restock: catat jika stok bertambah saat edit
            if stok > stok_lama:
                catat_restock(pid, stok - stok_lama, harga_beli)

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

        return jsonify({
            "ok": True,
            "id_terbaru": id_terbaru,
            "pesan": f"Produk '{nama}' berhasil disimpan"
        })
    except Exception as e:
        return jsonify({"ok": False, "pesan": str(e)}), 500


@app.route("/api/produk/<int:produk_id>", methods=["DELETE"])
@login_required
@admin_required
def api_hapus_produk(produk_id):
    try:
        conn = db.get_connection()
        row = conn.execute("SELECT gambar FROM produk WHERE id = ?", (produk_id,)).fetchone()
        if row and row["gambar"]:
            path_foto = os.path.join(FOLDER_IMG, row["gambar"])
            if os.path.exists(path_foto):
                os.remove(path_foto)

        conn.execute("DELETE FROM produk WHERE id = ?", (produk_id,))
        conn.commit()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "pesan": str(e)}), 500


# ==================== API KELOLA KATEGORI ====================

@app.route("/api/kategori", methods=["POST"])
@login_required
@admin_required
def api_tambah_kategori():
    data = request.get_json(silent=True) or {}
    nama = data.get("nama", "").strip()
    if not nama:
        return jsonify({"ok": False, "pesan": "Nama kategori kosong"}), 400
    conn = db.get_connection()
    conn.execute("INSERT OR IGNORE INTO kategori (nama) VALUES (?)", (nama,))
    conn.commit()
    return jsonify({"ok": True})


@app.route("/api/kategori/<int:kat_id>", methods=["PUT"])
@login_required
@admin_required
def api_edit_kategori(kat_id):
    data = request.get_json(silent=True) or {}
    nama_baru = data.get("nama", "").strip()
    if not nama_baru:
        return jsonify({"ok": False, "pesan": "Nama kategori tidak boleh kosong"}), 400
    conn = db.get_connection()
    lama = conn.execute("SELECT nama FROM kategori WHERE id = ?", (kat_id,)).fetchone()
    if lama:
        conn.execute("UPDATE kategori SET nama = ? WHERE id = ?", (nama_baru, kat_id))
        conn.execute("UPDATE produk SET kategori = ? WHERE kategori = ?", (nama_baru, lama["nama"]))
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/kategori/<int:kat_id>", methods=["DELETE"])
@login_required
@admin_required
def api_hapus_kategori(kat_id):
    conn = db.get_connection()
    conn.execute("DELETE FROM kategori WHERE id = ?", (kat_id,))
    conn.commit()
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
    bayar = int(float(data.get("bayar", 0) or 0))

    if not items:
        return jsonify({"ok": False, "pesan": "Keranjang masih kosong"}), 400

    try:
        conn = db.get_connection()
        cur = conn.cursor()
        tanggal = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        total_belanja = 0
        total_profit = 0
        detail_siap = []

        for item in items:
            pid = int(item["produk_id"])
            qty = int(item["jumlah"])
            prod = cur.execute("SELECT * FROM produk WHERE id = ?", (pid,)).fetchone()
            if not prod:
                return jsonify({"ok": False, "pesan": f"Produk ID {pid} tidak ditemukan"}), 400
            if prod["stok"] < qty:
                return jsonify({"ok": False, "pesan": f"Stok '{prod['nama']}' tidak mencukupi"}), 400

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
            return jsonify({"ok": False, "pesan": "Uang pembayaran kurang!"}), 400

        kembalian = bayar - total_belanja
        trx_cols = get_table_columns("transaksi")

        if "total_harga" in trx_cols and "total" not in trx_cols:
            cur.execute(
                "INSERT INTO transaksi (tanggal, total_harga, bayar, kembalian) VALUES (?, ?, ?, ?)",
                (tanggal, total_belanja, bayar, kembalian)
            )
        elif "keuntungan" in trx_cols:
            cur.execute(
                "INSERT INTO transaksi (tanggal, total, bayar, kembalian, keuntungan) VALUES (?, ?, ?, ?, ?)",
                (tanggal, total_belanja, bayar, kembalian, total_profit)
            )
        else:
            cur.execute(
                "INSERT INTO transaksi (tanggal, total, bayar, kembalian) VALUES (?, ?, ?, ?)",
                (tanggal, total_belanja, bayar, kembalian)
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
                "UPDATE produk SET stok = MAX(0, stok - ?) WHERE id = ?",
                (d["jumlah"], d["produk_id"])
            )

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
    except Exception as e:
        return jsonify({"ok": False, "pesan": str(e)}), 500


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

    for r in rows:
        d = dict(r)
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

        d["total_tampil"] = nom_total
        d["profit_tampil"] = nom_profit
        total_omzet += nom_total
        total_profit += nom_profit
        transaksi_list.append(d)

    return jsonify({
        "transaksi": transaksi_list,
        "total_omzet": total_omzet,
        "total_profit": total_profit,
        "jumlah_trx": len(transaksi_list)
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
            "bayar": t_dict.get("bayar", 0),
            "kembalian": t_dict.get("kembalian", 0),
            "items": [dict(i) for i in items]
        }
    })


@app.route("/api/riwayat/<int:trx_id>/retur", methods=["POST"])
@login_required
@admin_required
def api_retur_transaksi(trx_id):
    """Membatalkan transaksi dan mengembalikan stok produk."""
    try:
        conn = db.get_connection()
        items = conn.execute(
            "SELECT produk_id, jumlah FROM transaksi_detail WHERE transaksi_id = ?",
            (trx_id,)
        ).fetchall()

        for item in items:
            conn.execute(
                "UPDATE produk SET stok = stok + ? WHERE id = ?",
                (item["jumlah"], item["produk_id"])
            )

        conn.execute("DELETE FROM transaksi_detail WHERE transaksi_id = ?", (trx_id,))
        conn.execute("DELETE FROM transaksi WHERE id = ?", (trx_id,))
        conn.commit()
        return jsonify({"ok": True, "pesan": f"Transaksi #{trx_id} dibatalkan & stok dikembalikan"})
    except Exception as e:
        return jsonify({"ok": False, "pesan": str(e)}), 500


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
        FROM transaksi WHERE DATE(tanggal) = ?
    """, (hari_ini,)).fetchone()

    row_yesterday = conn.execute(f"""
        SELECT COALESCE(SUM({col_total}), 0) AS omzet
        FROM transaksi WHERE DATE(tanggal) = ?
    """, (kemarin,)).fetchone()

    profit_today_row = conn.execute("""
        SELECT COALESCE(SUM((td.harga_satuan - td.harga_beli) * td.jumlah), 0) AS profit
        FROM transaksi_detail td
        JOIN transaksi t ON td.transaksi_id = t.id
        WHERE DATE(t.tanggal) = ?
    """, (hari_ini,)).fetchone()

    top_produk = conn.execute("""
        SELECT td.nama_produk, SUM(td.jumlah) AS total_qty
        FROM transaksi_detail td
        JOIN transaksi t ON td.transaksi_id = t.id
        WHERE strftime('%Y-%m', t.tanggal) = ?
        GROUP BY td.produk_id, td.nama_produk
        ORDER BY total_qty DESC LIMIT 5
    """, (bulan_ini,)).fetchall()

    top_profit = conn.execute("""
        SELECT td.nama_produk,
               SUM((td.harga_satuan - td.harga_beli) * td.jumlah) AS total_profit
        FROM transaksi_detail td
        JOIN transaksi t ON td.transaksi_id = t.id
        WHERE strftime('%Y-%m', t.tanggal) = ?
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)