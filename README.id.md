# VsSession

[English](README.md) · **Bahasa Indonesia**

Ekstensi VS Code dengan dua fitur:

1. **Audit**: memeriksa hardening VS Code/Electron dan setup Claude Code, lalu menawarkan perbaikan yang aman (lihat file `AUDIT.md`).
2. **Organization Projects**: sesi Claude Code dibagikan dalam satu organisasi. Struktur tampilannya *Organisasi > Proyek > Anggota > Sesi*: sesi tiap anggota terpisah, tetapi semua anggota organisasi bisa melihatnya.

## Instalasi

```powershell
npm install
npm test            # build + 31 unit test
npm run package     # menghasilkan vssession-0.1.0.vsix
code --install-extension vssession-0.1.0.vsix
```

## Audit

Buka ikon **VsSession** di Activity Bar, lalu pilih **Audit → Run Audit**.

- **Fix**: mengubah setting user, lalu nilai efektifnya dibaca ulang. Bisa dibatalkan lewat `VsSession: Undo Last Audit Fix`. Undo menolak jika nilainya sudah Anda ubah lagi.
- **Review**: membuka file setting terkait, karena nilai berasal dari workspace atau file Claude.
- **Guidance**: tidak bisa diperbaiki otomatis. Contohnya fuse Electron, kebijakan admin, dan registry yang butuh hak administrator.
- **Apply All Safe Fixes** hanya mencakup temuan keamanan. Preferensi privasi dan update tidak pernah ikut.

## Organization Projects

### Penyiapan (sekali per organisasi)
1. Buat folder yang dibagikan ke semua anggota: folder OneDrive/SharePoint bersama, network share, atau repo git.
2. `VsSession: Create Organization in Shared Folder`, lalu pilih folder dan isi nama organisasi.
3. Bagikan folder itu ke anggota. **Akses ke folder adalah kontrol akses organisasi.** Siapa pun yang bisa membaca folder bisa melihat semua sesi di dalamnya.

### Untuk setiap anggota
1. `VsSession: Open Existing Organization Folder` lalu pilih folder bersama. Untuk OneDrive, set folder ke *Always keep on this device*.
2. Buka folder proyek, lalu `Link This Workspace to an Organization Project` (pilih proyek atau buat baru).
3. Bagikan sesi:
   - **Manual**: `Share a Claude Session…`. Sebelum dibagikan, ringkasan isi, tujuan, dan peringatan ditampilkan.
   - **Otomatis**: `Enable Auto-Share for This Workspace…` (butuh persetujuan eksplisit). Persetujuan otomatis batal jika folder tujuan, proyek, atau jenis konten berubah.

### Apa yang dibagikan
- Prompt, balasan Claude, nama tool beserta input/output yang dipotong.
- **Tidak** dibagikan: blok thinking, signature, account/organization UUID, field `cwd`.
- Redaksi diterapkan ke semua string sebelum dipotong: private key, token API (Anthropic, OpenAI, GitHub, GitLab, Slack, Stripe, Google, AWS, npm, HF), JWT, header Authorization, kredensial di URL, assignment `*_SECRET=`/`PASSWORD=` dan sejenisnya, email, path home, serta nama user. Pola tambahan bisa diatur lewat `vssession.publish.extraRedactPatterns`. **Redaksi bersifat best-effort**, jadi review sesi sensitif sebelum dibagikan.
- Sesi yang juga berjalan di luar folder workspace, tidak punya info `cwd`, atau memiliki record rusak **tidak pernah** dibagikan otomatis. Sesi seperti itu hanya bisa dibagikan manual setelah review.

### Struktur folder bersama
```
<root>/org.json
<root>/projects/<projectId>/project.json
<root>/projects/<projectId>/members/<memberId>/member.json
<root>/projects/<projectId>/members/<memberId>/devices/<deviceId>/sessions/<sessionId>/rev-<seq>-<rand>.json
```
- Setiap anggota dan perangkat hanya menulis ke foldernya sendiri, sehingga tidak ada konflik sinkronisasi.
- Revisi bersifat immutable dan self-contained, lengkap dengan hash SHA-256. File yang belum selesai tersinkron atau rusak diabaikan, dan revisi valid sebelumnya tetap tampil.
- Urutan revisi memakai nomor `seq`, bukan jam perangkat, jadi jam yang salah tidak bisa menyembunyikan revisi terbaru.
- Tiap perangkat menyimpan 3 revisi terakhir.

### Identitas
- Member ID dan device ID adalah UUID acak yang disimpan per mesin dan tidak ikut Settings Sync.
- Agar tampil sebagai anggota yang sama di beberapa komputer: `Export Member Identity` di komputer A, lalu `Import Member Identity` di komputer B.
- Nama tampilan diambil dari `vssession.member.displayName` (default: nama user OS). Nama ini **dilaporkan sendiri** oleh anggota dan bukan bukti identitas.

### Batasan
- Hanya workspace lokal. Untuk Remote SSH/WSL/Container, sesi Claude berada di host remote.
- **Git**: ekstensi hanya menulis file, jadi `git pull`/`git push` dilakukan sendiri. Status "published locally" berarti file sudah tertulis di folder lokal; pengiriman ke anggota lain bergantung pada klien sinkronisasi.
- Menghapus sesi hanya menghapus salinan dari perangkat ini. Salinan yang sudah tersinkron ke mesin lain tidak bisa ditarik.
- Workspace yang belum di-trust tidak bisa di-link atau membagikan sesi.

## Pengembangan
- `src/core/`: logika murni tanpa dependensi `vscode` dan bisa dites (fuses, redaksi, parser sesi, store organisasi, persetujuan).
- `src/audit/`: cek dan tampilan Audit.
- `src/org/`: controller, identitas, dan penampil transcript (webview tanpa script, CSP `default-src 'none'`).
