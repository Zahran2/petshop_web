"""Fungsi bantuan format angka untuk aplikasi Kasir & Stok Petshop."""


def format_ribuan(angka):
    """Ubah angka jadi string format ribuan ala Indonesia (tanpa prefix Rp).
    Contoh: 85000 -> '85.000'"""
    try:
        return f"{int(float(angka)):,}".replace(",", ".")
    except (ValueError, TypeError):
        return str(angka)


def format_rupiah(angka):
    """Format angka jadi 'Rp 85.000' lengkap dengan prefix."""
    return f"Rp {format_ribuan(angka)}"


def parse_angka(teks):
    """Ubah teks berformat ribuan menjadi integer murni.
    Contoh: '85.000' -> 85000."""
    bersih = "".join(c for c in str(teks).strip() if c.isdigit())
    if not bersih:
        raise ValueError("Masukkan angka yang valid")
    return int(bersih)