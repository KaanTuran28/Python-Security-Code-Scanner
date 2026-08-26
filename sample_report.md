# Python Security Code Scan Report

- **Files scanned:** 1
- **Findings:** 8 HIGH, 2 MEDIUM, 1 LOW

| Severity | File | Line | Check | Reason |
|---|---|---|---|---|
| HIGH | sample_code\insecure_example.py | 11 | hardcoded_secret_assignment | "DB_PASSWORD" is assigned a literal string that looks like a secret. |
| HIGH | sample_code\insecure_example.py | 12 | hardcoded_secret_assignment | "API_KEY" is assigned a literal string that looks like a secret. |
| HIGH | sample_code\insecure_example.py | 16 | shell_injection_risk | os.system() runs its argument through the shell — unsanitized input leads to command injection. |
| HIGH | sample_code\insecure_example.py | 17 | shell_injection_risk | "subprocess.run(..., shell=True)" runs the command through the shell — unsanitized input leads to command injection. |
| HIGH | sample_code\insecure_example.py | 22 | unsafe_deserialization | "pickle.load()" deserializes untrusted data into arbitrary Python objects — a crafted pickle payload can execute arbitrary code on load. |
| HIGH | sample_code\insecure_example.py | 27 | unsafe_deserialization | yaml.load() without Loader=yaml.SafeLoader can construct arbitrary Python objects from the YAML document, including ones that execute code on construction. |
| HIGH | sample_code\insecure_example.py | 40 | tls_verification_disabled | "requests.get(..., verify=False)" disables TLS certificate verification for this request, enabling MITM attacks. |
| HIGH | sample_code\insecure_example.py | 48 | eval_exec_usage | Call to "eval()" executes arbitrary code from its argument. |
| MEDIUM | sample_code\insecure_example.py | 31 | weak_hash_algorithm | "md5" is a cryptographically broken/weak hash — unsuitable for passwords, signatures, or integrity checks against an adversary. |
| MEDIUM | sample_code\insecure_example.py | 35 | insecure_randomness_for_security_value | "token" is derived from random.random(), which is not cryptographically secure and can be predicted or brute-forced. |
| LOW | sample_code\insecure_example.py | 44 | insecure_temp_file | tempfile.mktemp() returns a name without creating the file, leaving a race window where another process can create it first (TOCTOU). |
