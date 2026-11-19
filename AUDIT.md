# Laporan Audit VS Code & Claude Code

Tanggal: 2026-11-19 · Mesin: Windows 11 (x64)
Target: VS Code 1.146.0 (Electron 43.8.6, install per-user di `%LOCALAPPDATA%\Programs\Microsoft VS Code`) dan ekstensi `anthropic.claude-code` 2.1.326.

Metode: analisis statis dengan REA (`inspect_electron_fuses`, `analyze_javascript_application`), dilanjutkan pencarian terarah pada bundle JavaScript yang terpasang, lalu verifikasi konfigurasi di mesin. Tidak ada kode target yang dieksekusi.

Label: **Observasi**: dibaca langsung dari artefak atau konfigurasi. **Inferensi**: interpretasi kami. **Tidak diketahui**: belum diperiksa.

## Ringkasan temuan

| # | Temuan | Jenis | Dampak | Penanganan di VsSession |
|---|--------|-------|--------|-------------------------|
| 1 | Fuse `EnableEmbeddedAsarIntegrityValidation` dan `OnlyLoadAppFromAsar` **off**, dan install bersifat per-user (folder aplikasi bisa ditulis user) | Observasi + inferensi | Proses lokal apa pun yang berjalan sebagai user bisa memodifikasi JavaScript VS Code tanpa terdeteksi | Hanya dilaporkan. Mitigasi: gunakan *System Installer* VS Code (Program Files) |
| 2 | Fuse `RunAsNode`, `EnableNodeOptionsEnvironmentVariable`, `EnableNodeCliInspectArguments` **on** | Observasi | `ELECTRON_RUN_AS_NODE` / `NODE_OPTIONS` / `--inspect` memungkinkan injeksi kode ke `Code.exe` yang ditandatangani | Hanya dilaporkan, karena VS Code membutuhkannya (extension host, CLI). Audit memberi peringatan bila `NODE_OPTIONS` / `ELECTRON_RUN_AS_NODE` ter-set di environment |
| 3 | Fuse `EnableCookieEncryption` **off** | Observasi | Cookie Chromium (webview/alur login) tidak dienkripsi OS | Hanya dilaporkan |
| 4 | Sesi Claude di `~/.claude/projects` memiliki path > 260 karakter; `LongPathsEnabled = 0` | Observasi | Windows PowerShell 5.1, Explorer, serta tool backup/sync gagal membaca sesi tersebut | Perintah admin disalin ke clipboard. VsSession sendiri selalu membaca lewat prefix `\\?\`. Sesi tidak pernah dipindah otomatis |
| 5 | `git core.longpaths` belum diset | Observasi | Checkout repo dengan path panjang gagal (relevan jika folder organisasi berupa repo git) | Fix satu klik + verifikasi |
| 6 | Setting sensitif Claude (`claudeProcessWrapper`, `environmentVariables`, `allowDangerouslySkipPermissions`, `initialPermissionMode`) ber-scope `machine`; ekstensi `untrustedWorkspaces.supported = false` | Observasi (temuan positif) | Repo berbahaya **tidak bisa** menyetel setting ini lewat `.vscode/settings.json` | Audit tetap memeriksa nilai level user: wrapper yang dipasang, secret plaintext, `NODE_OPTIONS`, bypass permission |
| 7 | `claudeCode.claudeProcessWrapper` membuat ekstensi menjalankan executable dari setting tersebut, bukan binary bawaan (`Pse()` → `pathToClaudeCodeExecutable`) | Observasi (kode) | Siapa pun yang bisa menulis `settings.json` user bisa mengganti proses Claude | Dilaporkan bila diset |
| 8 | Setting keamanan VS Code yang dicek (nama dan nilai diverifikasi dari `workbench.desktop.main.js` build 1.146): `security.workspace.trust.enabled`, `security.workspace.trust.untrustedFiles`, `task.allowAutomaticTasks` (`on`/`off`), `chat.tools.global.autoApprove` (bisa dikunci policy), `security.promptFor{Local,Remote}FileProtocolHandling`, `http.proxyStrictSSL`, `extensions.verifySignature` | Observasi | Bergantung nilai di mesin | Fix hanya jika sumber nilai efektif adalah user/default; nilai dibaca ulang setelah fix; ada undo; scope workspace/policy hanya direview |

## Evidence REA

- `ev_1cd924a2e2ebfca3ba73319d7798b21c5508c9b89733f8a3e33ea49fa6d1a0f9`: fuse `Code.exe` (SHA-256 `4474ce7b…3eadb`, sentinel di offset 193223296). Direproduksi oleh tes `reproduces the REA observation on the installed Code.exe`.
- `ev_311aff7724288767cb2545ff170601d656f7172fe3fe8ddf4288f5081dfb19fd`: grafik aplikasi VS Code (`package.json`, `product.json`, `out/main.js`, `out/cli.js`). Cakupan parsial: 6214 file di luar seleksi.
- `ev_f8d69379b44c661ad6682e25c509d5c7faafc0dd2a4e3bda01fed6fbc290715d`: grafik ekstensi Claude Code. `webview/index.js` tidak selesai dianalisis (heap analyzer habis), sehingga bagian webview masih **tidak diketahui**.

## Tidak diperiksa (bukan berarti aman)

- Penyimpanan kredensial ekstensi Claude, tujuan jaringan, dan argumen subprocess secara lengkap.
- Isi `webview/index.js` ekstensi Claude.
- Perilaku runtime: semua temuan bersifat statis atau konfigurasi.
- Kebijakan Claude Code yang efektif. Audit hanya membaca `~/.claude/settings.json`, sedangkan setting proyek atau managed bisa menimpanya.
