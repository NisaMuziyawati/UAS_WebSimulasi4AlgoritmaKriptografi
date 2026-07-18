# CryptoLab — Web Simulasi Algoritma Kriptografi (DES · S-DES · AES · S-AES)

Aplikasi web untuk mensimulasikan empat algoritma enkripsi-dekripsi simetris — **DES**, **S-DES**, **AES-128**,
dan **S-AES** — lengkap dengan penjabaran proses perhitungan langkah demi langkah (key generation,
permutasi, substitusi S-Box, XOR, hingga hasil akhir), sebagai tugas UAS mata kuliah Kriptografi.

---

## ✨ Fitur

- Landing page dengan navigasi ke 4 modul algoritma.
- Setiap modul punya form input plaintext/ciphertext + key, toggle mode Enkripsi/Dekripsi, tombol
  Submit & Reset, kotak hasil, dan panel **"Tampilkan Solusi Penyelesaian"** yang bisa dibuka/tutup.
- Solusi penyelesaian ditampilkan sebagai accordion bertahap, mengikuti struktur:
  `Input → Key Generation → Initial Permutation/Round → Ronde 1..N (Expansion/SubBytes, XOR, S-Box,
  Permutasi/ShiftRows/MixColumns, hasil) → Final Permutation/Round`.
- Semua algoritma diimplementasikan dari nol di JavaScript murni (tanpa library kripto pihak ketiga)
  dan sudah diverifikasi terhadap test vector standar (lihat bagian **Validasi** di bawah).
- Menerima input biner maupun heksadesimal (otomatis dikonversi).
- Desain gelap "lab kriptografi" — responsif untuk desktop & mobile.

## 🗂️ Struktur Proyek

```
Web Simulasi 4 Algoritma Kriptografi/
├── index.html          # Landing page
├── des.html             # Modul DES (64-bit, 16 ronde, 8 S-Box)
├── sdes.html             # Modul S-DES (8-bit, 2 ronde, S0 & S1)
├── aes.html               # Modul AES-128 (128-bit, 10 ronde)
├── saes.html               # Modul S-AES (16-bit, 2 ronde)
├── css/
│   └── style.css        # Seluruh styling (dark theme, komponen bersama)
├── js/
│   ├── common.js         # Util bersama: konversi bit/hex, permutasi, XOR, GF(2^n), renderer accordion
│   ├── des.js             # Engine DES + jejak langkah
│   ├── sdes.js             # Engine S-DES + jejak langkah
│   ├── aes.js               # Engine AES-128 + jejak langkah
│   └── saes.js               # Engine S-AES + jejak langkah
└── README.md
```

Setiap algoritma dipisah ke file `.js` sendiri (mengembalikan objek modul, mis. `DES.run(...)`) supaya
mudah dibaca, diuji, dan dinilai terpisah. `common.js` menyediakan:

- `CL.toBits/hexToBin/binToHex` — normalisasi & konversi bit ⇄ hex
- `CL.permute` — permutasi tabel gaya buku teks (1-indexed)
- `CL.xor`, `CL.leftShift`, `CL.chunk`, `CL.gfMul` — operasi bit dasar & aritmetika GF(2ⁿ)
- `StepRenderer` — merender struktur langkah (`stepTree`) menjadi accordion "Solusi Penyelesaian"

## 🧠 Teknologi

- **HTML5 / CSS3 / Vanilla JavaScript (ES6)** — tanpa framework maupun build step, sehingga dapat
  langsung dijalankan atau di-hosting sebagai static site.
- Font: Space Grotesk (display), Inter (body), JetBrains Mono (nilai bit/hex/tabel) via Google Fonts.

## ▶️ Cara Menjalankan Secara Lokal

Karena murni HTML/CSS/JS statis, tidak perlu instalasi dependency apa pun.

```bash
git clone <URL_REPOSITORY_INI>
cd Web Simulasi 4 Algoritma Kriptografi

# opsi 1: buka langsung
open index.html          # macOS
start index.html         # Windows
xdg-open index.html      # Linux

# opsi 2 (disarankan, agar path relatif konsisten): jalankan local server
python3 -m http.server 8080
# lalu buka http://localhost:8080 di browser
```

## 🌐 Deployment

Aplikasi ini adalah static site sehingga bisa di-deploy ke penyedia hosting statis apa pun (GitHub
Pages, Netlify, Vercel, Cloudflare Pages, dll.) lalu dihubungkan ke domain `.my.id`. Langkah umum:

1. Push seluruh isi folder `Web Simulasi 4 Algoritma Kriptografi/` ke repository GitHub publik.
2. Aktifkan GitHub Pages (Settings → Pages → Deploy from branch), atau hubungkan repo ke Netlify/Vercel.
3. Daftarkan domain gratis `.my.id` (mis. via [domain.go.id](https://domain.go.id)) dan arahkan
   DNS/CNAME ke hasil deployment.

## ✅ Validasi Algoritma (Known-Answer Test)

Keempat *engine* di folder `js/` telah diuji terhadap test vector standar sebelum diintegrasikan ke UI:

| Algoritma | Plaintext | Key | Ciphertext (hasil) |
|---|---|---|---|
| DES  | `0123456789ABCDEF` | `133457799BBCDFF1` | `85E813540F0AB405` |
| S-DES | `10101010` | `1010000010` | `10001101` |
| AES-128 | `00112233445566778899AABBCCDDEEFF` | `00102030405060708090A0B0C0D0E0F` | `B4CAAFD63B02AF23659087641387BC0E` |
| S-AES | `1101011100101000` | `0100101011110101` | `0010010011101100` |

Nilai-nilai di atas sesuai dengan contoh baku pada literatur (Stallings — *Cryptography and Network
Security*; FIPS-197; Musa/Schaefer/Wedig — *A Simplified AES Algorithm*). Jalankan mode Dekripsi dengan
key & ciphertext yang sama untuk memverifikasi bahwa hasilnya kembali ke plaintext semula.

## 📎 Catatan Perhitungan Manual

Kasus uji yang dipakai pada dokumen perhitungan manual (scan PDF) menggunakan input yang **identik**
dengan yang diujikan pada aplikasi ini, agar hasil keduanya bisa dibandingkan langsung — sesuai
ketentuan pada soal UAS.

## 👤 Identitas

Nama : `[ Nisa Muziyawati ]`
NIM  : `[ 301230045 ]`
Mata Kuliah : Kriptografi
Perancangan dan Implementasi Web Simulasi 4 Algoritma Kriptografi: DES, S-DES, AES, dan S-AES
