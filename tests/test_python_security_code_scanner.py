import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from python_security_code_scanner import (
    build_json_report,
    build_report,
    collect_python_files,
    main,
    scan_file,
    scan_source,
)

SAMPLES = Path(__file__).resolve().parent.parent / "sample_code"


def checks_in(findings):
    return {f["check"] for f in findings}


def test_eval_flagged_high():
    findings = scan_source("eval(user_input)")
    assert any(f["check"] == "eval_exec_usage" and f["severity"] == "HIGH" for f in findings)


def test_exec_flagged_high():
    findings = scan_source("exec(user_input)")
    assert any(f["check"] == "eval_exec_usage" for f in findings)


def test_os_system_flagged_high():
    findings = scan_source("import os\nos.system(cmd)")
    assert any(f["check"] == "shell_injection_risk" and f["severity"] == "HIGH" for f in findings)


def test_subprocess_shell_true_flagged_high():
    findings = scan_source("import subprocess\nsubprocess.run(cmd, shell=True)")
    assert any(f["check"] == "shell_injection_risk" for f in findings)


def test_subprocess_shell_false_not_flagged():
    findings = scan_source("import subprocess\nsubprocess.run(['ls'], shell=False)")
    assert not any(f["check"] == "shell_injection_risk" for f in findings)


def test_subprocess_without_shell_kwarg_not_flagged():
    findings = scan_source("import subprocess\nsubprocess.run(['ls'])")
    assert not any(f["check"] == "shell_injection_risk" for f in findings)


def test_pickle_load_flagged_high():
    findings = scan_source("import pickle\npickle.load(f)")
    assert any(f["check"] == "unsafe_deserialization" and f["severity"] == "HIGH" for f in findings)


def test_pickle_loads_flagged_high():
    findings = scan_source("import pickle\npickle.loads(data)")
    assert any(f["check"] == "unsafe_deserialization" for f in findings)


def test_yaml_load_without_safe_loader_flagged_high():
    findings = scan_source("import yaml\nyaml.load(f, Loader=yaml.Loader)")
    assert any(f["check"] == "unsafe_deserialization" for f in findings)


def test_yaml_load_with_no_loader_kwarg_flagged_high():
    findings = scan_source("import yaml\nyaml.load(f)")
    assert any(f["check"] == "unsafe_deserialization" for f in findings)


def test_yaml_load_with_safe_loader_not_flagged():
    findings = scan_source("import yaml\nyaml.load(f, Loader=yaml.SafeLoader)")
    assert not any(f["check"] == "unsafe_deserialization" for f in findings)


def test_yaml_safe_load_not_flagged():
    findings = scan_source("import yaml\nyaml.safe_load(f)")
    assert not any(f["check"] == "unsafe_deserialization" for f in findings)


def test_md5_flagged_medium():
    findings = scan_source("import hashlib\nhashlib.md5(data)")
    assert any(f["check"] == "weak_hash_algorithm" and f["severity"] == "MEDIUM" for f in findings)


def test_sha1_flagged_medium():
    findings = scan_source("import hashlib\nhashlib.sha1(data)")
    assert any(f["check"] == "weak_hash_algorithm" for f in findings)


def test_sha256_not_flagged():
    findings = scan_source("import hashlib\nhashlib.sha256(data)")
    assert not any(f["check"] == "weak_hash_algorithm" for f in findings)


def test_tempfile_mktemp_flagged_low():
    findings = scan_source("import tempfile\ntempfile.mktemp()")
    assert any(f["check"] == "insecure_temp_file" and f["severity"] == "LOW" for f in findings)


def test_tempfile_mkstemp_not_flagged():
    findings = scan_source("import tempfile\ntempfile.mkstemp()")
    assert not any(f["check"] == "insecure_temp_file" for f in findings)


def test_ssl_create_unverified_context_flagged_high():
    findings = scan_source("import ssl\nssl._create_unverified_context()")
    assert any(f["check"] == "tls_verification_disabled" and f["severity"] == "HIGH" for f in findings)


def test_requests_verify_false_flagged_high():
    findings = scan_source("import requests\nrequests.get(url, verify=False)")
    assert any(f["check"] == "tls_verification_disabled" for f in findings)


def test_requests_verify_true_not_flagged():
    findings = scan_source("import requests\nrequests.get(url, verify=True)")
    assert not any(f["check"] == "tls_verification_disabled" for f in findings)


def test_hardcoded_password_assignment_flagged_high():
    findings = scan_source('PASSWORD = "hunter2"')
    assert any(f["check"] == "hardcoded_secret_assignment" and f["severity"] == "HIGH" for f in findings)


def test_hardcoded_secret_via_attribute_assignment_flagged():
    findings = scan_source('self.api_key = "sk_live_abc123"')
    assert any(f["check"] == "hardcoded_secret_assignment" for f in findings)


def test_password_from_env_not_flagged():
    findings = scan_source('import os\nPASSWORD = os.environ["PASSWORD"]')
    assert not any(f["check"] == "hardcoded_secret_assignment" for f in findings)


def test_empty_string_secret_assignment_not_flagged():
    findings = scan_source('PASSWORD = ""')
    assert not any(f["check"] == "hardcoded_secret_assignment" for f in findings)


def test_insecure_random_for_token_flagged_medium():
    findings = scan_source("import random\ntoken = random.random()")
    assert any(f["check"] == "insecure_randomness_for_security_value" and f["severity"] == "MEDIUM" for f in findings)


def test_secrets_module_for_token_not_flagged():
    findings = scan_source("import secrets\ntoken = secrets.token_urlsafe(32)")
    assert not any(f["check"] == "insecure_randomness_for_security_value" for f in findings)


def test_random_for_unrelated_variable_not_flagged():
    findings = scan_source("import random\ndice_roll = random.randint(1, 6)")
    assert not any(f["check"] == "insecure_randomness_for_security_value" for f in findings)


def test_line_numbers_are_reported():
    findings = scan_source("x = 1\ny = 2\neval(x)")
    eval_finding = next(f for f in findings if f["check"] == "eval_exec_usage")
    assert eval_finding["line"] == 3


def test_syntax_error_raises():
    try:
        scan_source("def broken(:\n")
        assert False, "expected SyntaxError"
    except SyntaxError:
        pass


# ---------------------------------------------------------------------------
# Real sample files
# ---------------------------------------------------------------------------

def test_insecure_example_file_flags_everything():
    findings = scan_file(SAMPLES / "insecure_example.py")
    checks = checks_in(findings)
    assert checks == {
        "eval_exec_usage",
        "shell_injection_risk",
        "unsafe_deserialization",
        "weak_hash_algorithm",
        "insecure_randomness_for_security_value",
        "tls_verification_disabled",
        "insecure_temp_file",
        "hardcoded_secret_assignment",
    }
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    assert (high, medium, low) == (8, 2, 1)


def test_hardened_example_file_has_no_findings():
    assert scan_file(SAMPLES / "hardened_example.py") == []


def test_collect_python_files_on_directory():
    files = collect_python_files(SAMPLES)
    names = {f.name for f in files}
    assert names == {"insecure_example.py", "hardened_example.py"}


def test_collect_python_files_on_single_file():
    files = collect_python_files(SAMPLES / "hardened_example.py")
    assert len(files) == 1


def test_build_report_lists_findings_in_markdown_table():
    results = [(str(SAMPLES / "insecure_example.py"), scan_file(SAMPLES / "insecure_example.py"))]
    report = build_report(results)
    assert "HIGH" in report
    assert "eval_exec_usage" in report


def test_build_report_clean_says_no_issues():
    results = [(str(SAMPLES / "hardened_example.py"), scan_file(SAMPLES / "hardened_example.py"))]
    report = build_report(results)
    assert "No issues found." in report


def test_json_report_is_valid_and_matches_findings():
    results = [(str(SAMPLES / "insecure_example.py"), scan_file(SAMPLES / "insecure_example.py"))]
    payload = json.loads(build_json_report(results))
    assert payload["files_scanned"] == 1
    assert payload["summary"]["high"] == 8


def run_main(monkeypatch, tmp_path, target_path, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["python_security_code_scanner.py", "--path", str(target_path), "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_for_insecure_example(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "insecure_example.py", ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_hardened_example(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "hardened_example.py", ["--fail-on", "high"]) == 0


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "insecure_example.py", []) == 0


def test_main_skips_files_with_syntax_errors(monkeypatch, tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n", encoding="utf-8")
    exit_code = run_main(monkeypatch, tmp_path, tmp_path, [])
    assert exit_code == 0
