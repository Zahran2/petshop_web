"""
Modul database untuk aplikasi Kasir & Stok Petshop.
Menggunakan SQLite bawaan Python (petshop.db) dengan koneksi per-thread dan mode WAL.
"""

import sqlite3
import os
import threading
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import utils

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "petshop.db")

_thread_local = threading.local()


def get_connection():
    """Mengembalikan koneksi SQLite per-thread dengan mode WAL dan busy_timeout."""
    conn = getattr(_thread_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA foreign_keys = ON")
        _thread_local.conn = conn
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()

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
        except sqlite3.OperationalError:
            pass

    cur.execute("""
        CREATE TABLE IF NOT EXISTS transaksi (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tanggal TEXT NOT NULL,
            total REAL NOT NULL,
            bayar REAL DEFAULT 0,
            kembalian REAL NOT NULL,
            keuntungan REAL DEFAULT 0,
            status TEXT DEFAULT 'selesai'
        )
    """)

    for col_sql in [
        "ALTER TABLE transaksi ADD COLUMN bayar REAL DEFAULT 0",
        "ALTER TABLE transaksi ADD COLUMN keuntungan REAL DEFAULT 0",
        "ALTER TABLE transaksi ADD COLUMN status TEXT DEFAULT 'selesai'"
    ]:
        try:
            cur.execute(col_sql)
        except sqlite3.OperationalError:
            pass

    cur.execute("""
        CREATE TABLE IF NOT EXISTS transaksi_detail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaksi_id INTEGER NOT NULL,
            produk_id INTEGER,
            nama_produk TEXT NOT NULL,
            harga_beli REAL DEFAULT 0,
            harga_satuan REAL NOT NULL,
            jumlah INTEGER NOT NULL,
            subtotal REAL NOT NULL,
            FOREIGN KEY (transaksi_id) REFERENCES transaksi(id),
            FOREIGN KEY (produk_id) REFERENCES produk(id) ON DELETE SET NULL
        )
    """)

    try:
        cur.execute("ALTER TABLE transaksi_detail ADD COLUMN harga_beli REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass

    cur.execute("""
        CREATE TABLE IF NOT EXISTS kategori (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama TEXT UNIQUE NOT NULL
        )
    """)

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
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pin TEXT NOT NULL,
            role TEXT NOT NULL,
            session_version INTEGER DEFAULT 1
        )
    """)

    try:
        cur.execute("ALTER TABLE users ADD COLUMN session_version INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass

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

    conn.commit()


# ---------------- PRODUK ----------------

def tambah_produk(nama, kategori, harga_beli, harga_jual, stok, satuan="pcs", gambar="", expired_date=""):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO produk (nama, kategori, harga_beli, harga_jual, stok, satuan, gambar, expired_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (nama, kategori, harga_beli, harga_jual, stok, satuan, gambar, expired_date),
    )
    id_baru = cur.lastrowid
    conn.commit()
    return id_baru


def update_produk(produk_id, nama, kategori, harga_beli, harga_jual, stok, satuan, gambar, expired_date):
    conn = get_connection()
    conn.execute(
        "UPDATE produk SET nama=?, kategori=?, harga_beli=?, harga_jual=?, stok=?, satuan=?, gambar=?, expired_date=? WHERE id=?",
        (nama, kategori, harga_beli, harga_jual, stok, satuan, gambar, expired_date, produk_id),
    )
    conn.commit()


def hapus_produk(produk_id):
    conn = get_connection()
    conn.execute("DELETE FROM produk WHERE id=?", (produk_id,))
    conn.commit()


def get_semua_produk(keyword=None, kategori=None, limit=None, offset=0):
    conn = get_connection()
    query = "SELECT * FROM produk WHERE 1=1"
    params = []

    if keyword:
        query += " AND nama LIKE ?"
        params.append(f"%{keyword}%")

    if kategori and kategori != "Semua Kategori":
        query += " AND kategori = ?"
        params.append(kategori)

    query += " ORDER BY LOWER(nama)"

    if limit is not None:
        query += " LIMIT ? OFFSET ?"
        params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_produk_by_id(produk_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM produk WHERE id=?", (produk_id,)).fetchone()
    return dict(row) if row else None


# ---------------- KATEGORI ----------------

def tambah_kategori(nama):
    conn = get_connection()
    conn.execute("INSERT OR IGNORE INTO kategori (nama) VALUES (?)", (nama,))
    conn.commit()


def get_semua_kategori():
    conn = get_connection()
    rows = conn.execute("SELECT nama FROM kategori ORDER BY LOWER(nama)").fetchall()
    return [r["nama"] for r in rows]


def update_kategori(kategori_id, nama_baru):
    conn = get_connection()
    try:
        conn.execute("UPDATE kategori SET nama=? WHERE id=?", (nama_baru, kategori_id))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()


def hapus_kategori(kategori_id):
    conn = get_connection()
    conn.execute("DELETE FROM kategori WHERE id=?", (kategori_id,))
    conn.commit()


def get_kategori_lengkap():
    conn = get_connection()
    rows = conn.execute("SELECT id, nama FROM kategori ORDER BY LOWER(nama)").fetchall()
    return [dict(r) for r in rows]


# ---------------- TRANSAKSI ----------------

def buat_transaksi(items, dibayar):
    if not items:
        raise ValueError("Keranjang masih kosong")

    conn = get_connection()
    cur = conn.cursor()
    total_keuntungan = 0

    try:
        if not conn.in_transaction:
            cur.execute("BEGIN IMMEDIATE")

        for item in items:
            row = cur.execute(
                "SELECT stok, nama, harga_beli FROM produk WHERE id=?",
                (item["produk_id"],)
            ).fetchone()
            if row is None:
                raise ValueError(f"Produk '{item['nama_produk']}' tidak ditemukan di database")
            if row["stok"] < item["jumlah"]:
                raise ValueError(
                    f"Stok '{row['nama']}' tidak cukup - tersedia {row['stok']}, diminta {item['jumlah']}"
                )
            item["db_harga_beli"] = row["harga_beli"]

        total = sum(item["harga_satuan"] * item["jumlah"] for item in items)
        kembalian = dibayar - total

        if kembalian < 0:
            raise ValueError(
                f"Uang dibayar (Rp {utils.format_ribuan(dibayar)}) kurang dari total (Rp {utils.format_ribuan(total)})"
            )

        for item in items:
            profit_per_item = (item["harga_satuan"] - item["db_harga_beli"]) * item["jumlah"]
            total_keuntungan += profit_per_item

        tanggal = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            "INSERT INTO transaksi (tanggal, total, bayar, kembalian, keuntungan, status) VALUES (?, ?, ?, ?, ?, 'selesai')",
            (tanggal, total, dibayar, kembalian, total_keuntungan),
        )
        transaksi_id = cur.lastrowid

        for item in items:
            subtotal = item["harga_satuan"] * item["jumlah"]
            cur.execute(
                """INSERT INTO transaksi_detail
                   (transaksi_id, produk_id, nama_produk, harga_satuan, jumlah, subtotal, harga_beli)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (transaksi_id, item["produk_id"], item["nama_produk"],
                 item["harga_satuan"], item["jumlah"], subtotal, item["db_harga_beli"]),
            )
            cur.execute(
                "UPDATE produk SET stok = stok - ? WHERE id = ? AND stok >= ?",
                (item["jumlah"], item["produk_id"], item["jumlah"])
            )
            if cur.rowcount == 0:
                raise ValueError(f"Stok '{item['nama_produk']}' berubah saat transaksi diproses")

        conn.commit()
        return transaksi_id, total, kembalian
    except Exception:
        conn.rollback()
        raise


def get_riwayat_transaksi(filter_waktu="Semua Waktu"):
    conn = get_connection()
    query = "SELECT * FROM transaksi"
    params = []
    today = datetime.now()

    if filter_waktu == "Hari Ini":
        query += " WHERE tanggal LIKE ?"
        params.append(f"{today.strftime('%Y-%m-%d')}%")
    elif filter_waktu == "7 Hari Terakhir":
        tujuh_hari_lalu = (today - timedelta(days=7)).strftime("%Y-%m-%d")
        query += " WHERE tanggal >= ?"
        params.append(tujuh_hari_lalu)
    elif filter_waktu == "Bulan Ini":
        query += " WHERE tanggal LIKE ?"
        params.append(f"{today.strftime('%Y-%m')}%")

    query += " ORDER BY id DESC"
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_detail_transaksi(transaksi_id):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM transaksi_detail WHERE transaksi_id=?", (transaksi_id,)
    ).fetchall()
    return [dict(r) for r in rows]


def verifikasi_login(username, pin):
    if not username or not pin:
        return None
    conn = get_connection()
    user = conn.execute(
        "SELECT pin, role FROM users WHERE username = ?",
        (username.strip().lower(),)
    ).fetchone()
    if not user:
        return None

    pin_db = str(user["pin"] or "")
    if pin_db.startswith(("scrypt:", "pbkdf2:")):
        return user["role"] if check_password_hash(pin_db, pin) else None
    return user["role"] if pin_db == pin else None