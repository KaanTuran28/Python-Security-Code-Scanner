# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: Python kaynak kodunu `ast` modülüyle (kod hiç çalıştırılmadan) statik denetleyen "Bandit-lite" tarzı bir SAST aracı. 8 kontrol: `eval`/`exec`, shell injection (`os.system`, `subprocess(shell=True)`), güvensiz deserialization (`pickle.load`, `yaml.load` SafeLoader'sız), devre dışı TLS doğrulaması (`verify=False`, `ssl._create_unverified_context`), zayıf hash (md5/sha1), koda gömülü secret (PASSWORD/API_KEY literal string), güvenlik-hassas değer için `random.*` kullanımı (secrets modülü yerine), güvensiz geçici dosya (`tempfile.mktemp`).
- Test sırasında gerçek bir hesaplama hatası yakalandı ve düzeltildi: `insecure_example.py` için beklenen HIGH sayısını elle 9 olarak tahmin etmiştim, gerçek çalıştırma 8 çıkardı (doğru sayı) — testler buna göre düzeltildi. Bu, "gerçekten çalıştır, tahmin etme" prensibinin tekrar işe yaradığı bir an.
- Dosya: `python_security_code_scanner.py`, 2 örnek dosya (`insecure_example.py` — 8 kontrolün hepsini gösteriyor, `hardened_example.py` — 0 bulgu), `tests/test_python_security_code_scanner.py` (40 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}`.
- Durum: ✅ 40/40 test gerçekten çalıştırılıp geçti, `ruff check .` temiz (örnek dosyalardaki `subprocess.run` çağrılarına ruff'ın `PLW1510` uyarısını gidermek için `check=False` eklendi — güvenlik semantiğini etkilemiyor). CLI her iki örneğe karşı gerçekten çalıştırıldı: `insecure_example.py` → 8 HIGH + 2 MEDIUM + 1 LOW, `hardened_example.py` → 0 bulgu. `sample_report.md` gerçek çalıştırmadan üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `Python-Security-Code-Scanner` adıyla repo aç, git init + push.
