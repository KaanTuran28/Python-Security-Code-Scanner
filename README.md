# Python Security Code Scanner

![CI](https://github.com/KaanTuran28/Python-Security-Code-Scanner/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A static, AST-based security scanner for Python source code — a small, focused "Bandit-lite". Parses each file with the standard library `ast` module (the code is never executed) and flags a high-signal set of insecure patterns.

### Overview

- **`eval`/`exec`** — arbitrary code execution from a runtime string.
- **Shell injection** — `os.system(...)`, or `subprocess.run/call/Popen(..., shell=True)`.
- **Unsafe deserialization** — `pickle.load`/`pickle.loads`, or `yaml.load(...)` without `Loader=yaml.SafeLoader`.
- **Disabled TLS verification** — `requests.get(..., verify=False)`, `ssl._create_unverified_context()`.
- **Weak hash algorithms** — `hashlib.md5`/`hashlib.sha1`.
- **Hardcoded secrets** — a `PASSWORD`/`API_KEY`/`*_SECRET`/`*_TOKEN`-like variable assigned a literal string.
- **Insecure randomness for security values** — `random.*` feeding a variable named like `token`/`key`/`secret`/`nonce`, instead of the `secrets` module.
- **Insecure temp files** — `tempfile.mktemp()` (race-condition-prone; use `mkstemp()`).

### Installation

Requires Python 3.9+. No external dependencies.

```bash
git clone <this-repo>
cd Python-Security-Code-Scanner
pip install -e .
```

This installs a `python-security-code-scanner` command. You can also run the script directly with `python python_security_code_scanner.py` without installing.

### Usage

```bash
python-security-code-scanner --path myapp/ --output report.md
python-security-code-scanner --path myscript.py --format json --output report.json
```

| Flag | Default | Description |
|---|---|---|
| `--path` | *(required)* | A single `.py` file, or a directory to scan recursively |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

A file with a syntax error is skipped with a warning on stderr rather than aborting the whole scan.

### CI Integration

```bash
python-security-code-scanner --path src/ --fail-on high
```

```yaml
# GitHub Actions step
- name: Static security scan (Python)
  run: python-security-code-scanner --path src/ --fail-on high
```

Default is `none` (always exits `0`) so ad-hoc scanning is unaffected.

### Example Output

[`sample_code/insecure_example.py`](./sample_code/insecure_example.py) intentionally contains every check above; [`sample_code/hardened_example.py`](./sample_code/hardened_example.py) is its fixed counterpart (env-sourced secret, `shell=False`, `yaml.safe_load`, `sha256`, `secrets.token_urlsafe`, `verify=True`, `mkstemp`) and produces **zero findings**. See [`sample_report.md`](./sample_report.md) — real output from scanning `insecure_example.py`: 8 HIGH, 2 MEDIUM, 1 LOW.

### Limitations

This is a small, curated set of high-signal checks, not a comprehensive SAST tool — it won't catch everything Bandit/Semgrep would, and every check here is a syntactic pattern match on the AST, not a full data-flow analysis (e.g. it won't trace a secret through several variable reassignments before it reaches a hardcoded string). Treat it as a fast first pass, not a replacement for a real SAST/DAST pipeline.

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Project Structure

```
Python-Security-Code-Scanner/
├── python_security_code_scanner.py
├── pyproject.toml
├── sample_code/
│   ├── insecure_example.py
│   └── hardened_example.py
├── sample_report.md
├── tests/
│   └── test_python_security_code_scanner.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

Python kaynak kodu için statik, AST tabanlı bir güvenlik tarayıcısı — küçük, odaklanmış bir "Bandit-lite". Her dosyayı standart kütüphanenin `ast` modülüyle ayrıştırır (kod asla çalıştırılmaz) ve yüksek sinyalli bir güvensiz kalıp kümesini işaretler.

### Genel Bakış

- **`eval`/`exec`** — çalışma zamanı dizgisinden keyfi kod yürütme.
- **Shell injection (kabuk enjeksiyonu)** — `os.system(...)`, veya `subprocess.run/call/Popen(..., shell=True)`.
- **Güvensiz deserialization (serileştirmeden çıkarma)** — `pickle.load`/`pickle.loads`, veya `Loader=yaml.SafeLoader` olmadan `yaml.load(...)`.
- **Devre dışı bırakılmış TLS doğrulaması** — `requests.get(..., verify=False)`, `ssl._create_unverified_context()`.
- **Zayıf hash algoritmaları** — `hashlib.md5`/`hashlib.sha1`.
- **Koda gömülü (hardcoded) sırlar** — `PASSWORD`/`API_KEY`/`*_SECRET`/`*_TOKEN` benzeri bir değişkene sabit bir dizgi atanması.
- **Güvenlik değerleri için güvensiz rastgelelik** — `secrets` modülü yerine, `token`/`key`/`secret`/`nonce` gibi adlandırılmış bir değişkeni besleyen `random.*`.
- **Güvensiz geçici dosyalar** — `tempfile.mktemp()` (race condition'a açık; bunun yerine `mkstemp()` kullanın).

### Kurulum

Python 3.9+ gerektirir. Harici bağımlılık yoktur.

```bash
git clone <this-repo>
cd Python-Security-Code-Scanner
pip install -e .
```

Bu, bir `python-security-code-scanner` komutu kurar. Kurulum yapmadan da doğrudan `python python_security_code_scanner.py` ile betiği çalıştırabilirsiniz.

### Kullanım

```bash
python-security-code-scanner --path myapp/ --output report.md
python-security-code-scanner --path myscript.py --format json --output report.json
```

| Flag | Varsayılan | Açıklama |
|---|---|---|
| `--path` | *(zorunlu)* | Tek bir `.py` dosyası veya özyinelemeli olarak taranacak bir dizin |
| `--output` | `sample_report.md` | Raporun yazılacağı yol |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium` veya `high` — bu önem derecesinde veya üzerinde bir bulgu varsa çıkış kodu `1` |

Sözdizimi hatası olan bir dosya, tüm taramayı iptal etmek yerine stderr'e bir uyarı yazılarak atlanır.

### CI Entegrasyonu

```bash
python-security-code-scanner --path src/ --fail-on high
```

```yaml
# GitHub Actions adımı
- name: Static security scan (Python)
  run: python-security-code-scanner --path src/ --fail-on high
```

Varsayılan değer `none`'dur (her zaman `0` ile çıkar), böylece ad-hoc taramalar etkilenmez.

### Örnek Çıktı

[`sample_code/insecure_example.py`](./sample_code/insecure_example.py) yukarıdaki her kontrolü kasıtlı olarak içerir; [`sample_code/hardened_example.py`](./sample_code/hardened_example.py) ise onun düzeltilmiş karşılığıdır (ortam değişkeninden alınan sır, `shell=False`, `yaml.safe_load`, `sha256`, `secrets.token_urlsafe`, `verify=True`, `mkstemp`) ve **sıfır bulgu** üretir. `insecure_example.py` taramasından gerçek çıktı için [`sample_report.md`](./sample_report.md) dosyasına bakın: 8 HIGH, 2 MEDIUM, 1 LOW.

### Sınırlamalar

Bu, kapsamlı bir SAST aracı değil, küçük ve derlenmiş, yüksek sinyalli bir kontroller kümesidir — Bandit/Semgrep'in yakalayacağı her şeyi yakalamaz ve buradaki her kontrol, tam bir veri akışı (data-flow) analizi değil, AST üzerinde sözdizimsel bir kalıp eşleştirmesidir (örn. bir sırrın, koda gömülü bir dizgiye ulaşmadan önce birkaç değişken yeniden atamasından geçtiğini izlemez). Bunu gerçek bir SAST/DAST hattının yerine değil, hızlı bir ilk geçiş olarak değerlendirin.

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Proje Yapısı

```
Python-Security-Code-Scanner/
├── python_security_code_scanner.py
├── pyproject.toml
├── sample_code/
│   ├── insecure_example.py
│   └── hardened_example.py
├── sample_report.md
├── tests/
│   └── test_python_security_code_scanner.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
