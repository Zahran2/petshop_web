# 🐾 Petshop POS & Inventory Web App

Aplikasi web ringan untuk manajemen **Kasir (Point of Sale)**, **Stok Barang**, **Riwayat Transaksi**, dan **Dashboard Analitik** khusus toko petshop. Dirancang responsif agar nyaman dibuka melalui **HP (Android/iPhone)** maupun **Laptop/PC** secara *real-time* menggunakan satu database terpusat.

---

## ✨ Fitur Utama

### 1. 🔐 Sistem Login & Hak Akses (Role-Based Access)
* **Mode Admin (`admin`):** Akses penuh ke seluruh menu (**Kasir**, **Stok**, **Riwayat**, dan **Dashboard**), termasuk melihat harga modal, keuntungan bersih, serta membatalkan transaksi.
* **Mode Kasir (`kasir`):** Tampilan khusus layar kasir untuk karyawan. Menu stok, riwayat omzet, profit, dan harga modal otomatis disembunyikan serta diblokir dari sisi server.
* **Sesi Persisten:** Mendukung sesi login aktif selama 30 hari di browser HP agar tidak perlu berulang kali mengetik PIN.

### 2. 🛒 Layar Kasir Cepat (POS)
* **Pencarian Instan & Barcode Ready:** Mendukung pencarian nama produk secara *real-time* serta tombol `Enter` untuk langsung memasukkan barang ke keranjang jika hasil pencarian cocok 1 produk.
* **Filter Kategori & Paginasi:** Dilengkapi filter kategori dan pembagian halaman (`Prev` / `Next`, 30 barang per halaman) agar tetap ringan saat memuat ribuan produk.
* **Manajemen Keranjang & Pembayaran Cepat:** Tombol tambah/kurang jumlah, hapus per item (`✕`), kosongkan keranjang, serta tombol uang cepat (**Uang Pas**, **Rp 20.000**, **Rp 50.000**, **Rp 100.000**).
* **Struk Digital:** Menghasilkan nota pembayaran yang dapat diunduh sebagai file `.txt` (format lebar kertas thermal 58mm).

### 3. 📦 Manajemen Stok & Auto-Kompresi Foto
* **Kompresi Foto Otomatis:** Foto yang diunggah atau dijepret langsung dari kamera HP otomatis diperbaiki orientasinya, diperkecil ke dimensi maksimal `300x300` piksel, dan dikonversi menjadi `.jpg` ringan ($\approx 20\text{ KB}$ per foto) sehingga hemat penyimpanan server.
* **Input Cepat (*Simpan & Tambah Lagi*):** Mempermudah input banyak barang sekaligus tanpa menutup jendela form, lengkap dengan sorotan warna biru pada produk yang baru ditambahkan.
* **Pelacakan Kadaluarsa (*Expired Date*):** Indikator warna otomatis untuk barang yang sudah *expired* atau mendekati masa kadaluarsa ($\le 90$ hari).
* **Filter Cerdas & Pengurutan:** Filter cepat untuk **Stok Menipis ($\le 5$)**, **Barang Susah Laku / Dead Stock (30 hari tidak terjual)**, dan **Mendekati Expired**, serta pengurutan abjad, stok tersedikit, atau harga tertinggi.
* **Smart Restock & Kelola Kategori:** Penambahan stok saat edit produk otomatis dicatat ke dalam **Riwayat Barang Masuk (Kulakan)**. Dilengkapi manajemen kategori (Tambah, Edit, Hapus) dan **Export CSV**.

### 4. 📜 Riwayat Transaksi & Retur
* **Filter Periode:** Menampilkan riwayat transaksi berdasarkan **Hari Ini**, **7 Hari Terakhir**, **Bulan Ini**, atau **Semua Waktu**.
* **Perhitungan Profit Akurat:** Mengunci nominal harga modal saat transaksi terjadi sehingga laporan keuntungan tetap akurat meskipun harga *supplier* berubah di kemudian hari.
* **Pembatalan Transaksi (Retur):** Khusus Admin—menghapus nota yang salah input dan otomatis mengembalikan stok produk ke rak.
* **Export Laporan CSV:** Unduh rekap omzet dan keuntungan bersih untuk dibuka di Microsoft Excel atau Google Sheets.

### 5. 📊 Dashboard Analitik
* Perbandingan **Omzet Hari Ini vs Kemarin** beserta indikator naik/turun.
* Ringkasan **Profit Bersih Hari Ini** dan jumlah transaksi.
* Peringatan cepat jumlah produk **Stok Menipis** dan **Mendekati Expired** yang dapat diklik langsung menuju daftar barangnya.
* Peringkat **Kategori Paling Cuan**, **Top 5 Produk Paling Laris**, dan **Top 5 Pahlawan Profit** bulan berjalan.

### 6. ♿ Aksesibilitas Ramah Orang Tua
* Dilengkapi tombol pengatur ukuran huruf (**`A-`** / **`A+`**) di bagian atas layar untuk memperbesar teks hingga `130%` agar mudah dibaca di layar HP.

---

## 🛠️ Teknologi yang Digunakan

* **Backend:** Python 3, Flask
* **Database:** SQLite3 (`petshop.db`)
* **Pengolah Gambar:** Pillow (`PIL`)
* **Frontend:** HTML5, Tailwind CSS, Vanilla JavaScript

---

## 📁 Struktur Folder Project

```text
petshop_web/
├── web_app.py              # Server utama Flask, API endpoint, & kompresi foto
├── db.py                   # Koneksi dan fungsi database SQLite
├── utils.py                # Fungsi utilitas pendukung
├── petshop.db              # File database SQLite (otomatis dibuat jika belum ada)
├── img_produk/             # Folder penyimpanan foto produk terkompresi
└── templates/
    ├── login.html          # Halaman login (Username & PIN)
    └── index.html          # Antarmuka utama (Kasir, Stok, Riwayat, Dashboard)
```

---

## 🔑 Akun Login Bawaan

Saat pertama kali dijalankan, sistem otomatis membuat dua akun bawaan:

| Peran (Role) | Username | Hak Akses |
| :--- | :--- | :--- | :--- |
| **Admin / Pemilik** | `admin` | Semua menu (Kasir, Stok, Riwayat, Dashboard, Retur) |
| **Kasir / Karyawan** | `kasir` | Hanya menu Kasir |

> **Catatan Keamanan:** Segera ubah PIN bawaan di tabel `users` pada database `petshop.db` sebelum digunakan untuk operasional toko.

---

## 🚀 Cara Menjalankan di Komputer / Wi-Fi Lokal

1. Pastikan **Python 3** sudah terinstal di komputer.
2. Buka terminal/CMD di dalam folder `petshop_web`, lalu instal pustaka yang dibutuhkan:
   ```bash
   pip install flask pillow
   ```
3. Jalankan server aplikasi:
   ```bash
   python web_app.py
   ```
4. Buka browser dan akses:
   * **Di Laptop/PC:** `http://127.0.0.1:5000`
   * **Di HP (Wi-Fi yang sama):** `http://<IP-LOKAL-LAPTOP>:5000` (cek IP lokal melalui perintah `ipconfig` di Windows atau `ifconfig` di Linux/Mac).

---

## ☁️ Panduan Singkat Deploy Online (PythonAnywhere)

1. Kompres seluruh isi folder `petshop_web` menjadi file `.zip`.
2. Unggah file `.zip` tersebut ke menu **Files** di akun [PythonAnywhere](https://www.pythonanywhere.com/), lalu ekstrak melalui **Bash Console**:
   ```bash
   unzip petshop_web.zip -d petshop_web
   pip install --user flask pillow
   ```
3. Buka tab **Web** $\rightarrow$ buat aplikasi web baru (**Manual Configuration**) $\rightarrow$ atur **Source code** ke `/home/<username>/petshop_web`.
4. Edit file **WSGI configuration** agar mengarah ke `web_app`:
   ```python
   import sys

   path = '/home/<username>/petshop_web'
   if path not in sys.path:
       sys.path.insert(0, path)

   from web_app import app as application
   ```
5. Klik **Save**, lalu tekan tombol hijau **Reload** pada tab **Web**.
6. Buka alamat `https://<username>.pythonanywhere.com` di browser HP dan pilih **Tambahkan ke Layar Utama (Add to Home Screen)** agar dapat diakses layaknya aplikasi mobile.
