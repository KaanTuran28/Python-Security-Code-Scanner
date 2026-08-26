#!/usr/bin/env python3
"""AST-based static security scanner for Python source code.

Walks the Python `ast` for a file (no execution of the scanned code) and
flags a small, high-signal set of insecure patterns: eval/exec, shell
injection via os.system/subprocess(shell=True), unsafe deserialization
(pickle, unsafe yaml.load), disabled TLS verification, weak hashes,
hardcoded secrets, insecure temp files, and non-cryptographic randomness
used for security-sensitive values. Pure standard library (`ast`) — no
third-party linter required.
"""

import argparse
import ast
import json
import re
import sys
from pathlib import Path

SECRET_NAME_RE = re.compile(r"(password|secret|token|api_?key|private_key|access_key)", re.IGNORECASE)
SECURITY_VALUE_NAME_RE = re.compile(r"(token|secret|password|key|otp|nonce|csrf)", re.IGNORECASE)
WEAK_HASH_FUNCS = {"md5", "sha1"}
SHELL_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_call", "subprocess.check_output"}
HTTP_FUNCS = {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.patch", "requests.request"}


def dotted_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def finding(severity: str, check: str, line: int, reason: str, recommendation: str, snippet: str = "") -> dict:
    return {
        "severity": severity,
        "check": check,
        "line": line,
        "reason": reason,
        "recommendation": recommendation,
        "snippet": snippet,
    }


class SecurityVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: list):
        self.source_lines = source_lines
        self.findings = []

    def _snippet(self, node) -> str:
        try:
            return self.source_lines[node.lineno - 1].strip()
        except IndexError:
            return ""

    def _add(self, severity, check, node, reason, recommendation):
        self.findings.append(finding(severity, check, node.lineno, reason, recommendation, self._snippet(node)))

    def visit_Call(self, node: ast.Call):
        name = dotted_name(node.func)

        if name in ("eval", "exec"):
            self._add(
                "HIGH", "eval_exec_usage", node,
                f'Call to "{name}()" executes arbitrary code from its argument.',
                "Avoid eval/exec entirely; use ast.literal_eval for data, or an explicit dispatch table for logic.",
            )

        elif name == "os.system":
            self._add(
                "HIGH", "shell_injection_risk", node,
                "os.system() runs its argument through the shell — unsanitized input leads to command injection.",
                "Use subprocess.run([...], shell=False) with an argument list instead of a shell string.",
            )

        elif name in SHELL_FUNCS and any(
            kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in node.keywords
        ):
            self._add(
                "HIGH", "shell_injection_risk", node,
                f'"{name}(..., shell=True)" runs the command through the shell — unsanitized input leads '
                "to command injection.",
                "Pass an argument list and use shell=False (the default), avoiding shell string interpolation.",
            )

        elif name in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"):
            self._add(
                "HIGH", "unsafe_deserialization", node,
                f'"{name}()" deserializes untrusted data into arbitrary Python objects — a crafted pickle '
                "payload can execute arbitrary code on load.",
                "Never unpickle data from an untrusted source; use JSON or another safe, data-only format.",
            )

        elif name == "yaml.load":
            loader_kw = next((kw for kw in node.keywords if kw.arg == "Loader"), None)
            loader_name = dotted_name(loader_kw.value) if loader_kw else ""
            if not loader_name.endswith("SafeLoader"):
                self._add(
                    "HIGH", "unsafe_deserialization", node,
                    "yaml.load() without Loader=yaml.SafeLoader can construct arbitrary Python objects "
                    "from the YAML document, including ones that execute code on construction.",
                    "Use yaml.safe_load(...), or yaml.load(..., Loader=yaml.SafeLoader) explicitly.",
                )

        elif name in ("hashlib.md5", "hashlib.sha1"):
            algo = name.rsplit(".", 1)[-1]
            self._add(
                "MEDIUM", "weak_hash_algorithm", node,
                f'"{algo}" is a cryptographically broken/weak hash — unsuitable for passwords, signatures, '
                "or integrity checks against an adversary.",
                "Use hashlib.sha256 (or better) for integrity; use a password-hashing KDF (bcrypt/scrypt/argon2) "
                "for credentials, never a plain fast hash.",
            )

        elif name == "tempfile.mktemp":
            self._add(
                "LOW", "insecure_temp_file", node,
                "tempfile.mktemp() returns a name without creating the file, leaving a race window where "
                "another process can create it first (TOCTOU).",
                "Use tempfile.mkstemp() (or the NamedTemporaryFile/TemporaryDirectory context managers) instead.",
            )

        elif name == "ssl._create_unverified_context":
            self._add(
                "HIGH", "tls_verification_disabled", node,
                "ssl._create_unverified_context() disables certificate verification for any connection "
                "using this context, enabling MITM attacks.",
                "Use ssl.create_default_context() and fix the underlying certificate/hostname issue instead.",
            )

        elif name in HTTP_FUNCS and any(
            kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
            for kw in node.keywords
        ):
            self._add(
                "HIGH", "tls_verification_disabled", node,
                f'"{name}(..., verify=False)" disables TLS certificate verification for this request, '
                "enabling MITM attacks.",
                "Remove verify=False and fix the underlying certificate issue (e.g. supply a CA bundle).",
            )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for target in node.targets:
            target_name = None
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr

            if target_name and SECRET_NAME_RE.search(target_name) and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, str) and node.value.value:
                self._add(
                    "HIGH", "hardcoded_secret_assignment", node,
                    f'"{target_name}" is assigned a literal string that looks like a secret.',
                    "Load secrets from an environment variable, secret manager, or config file excluded "
                    "from version control — never as a literal in source.",
                )

            if target_name and SECURITY_VALUE_NAME_RE.search(target_name) and isinstance(node.value, ast.Call):
                call_name = dotted_name(node.value.func)
                if call_name.startswith("random."):
                    self._add(
                        "MEDIUM", "insecure_randomness_for_security_value", node,
                        f'"{target_name}" is derived from {call_name}(), which is not cryptographically '
                        "secure and can be predicted or brute-forced.",
                        'Use the "secrets" module (e.g. secrets.token_urlsafe/token_hex) for anything '
                        "security-sensitive (tokens, session IDs, passwords, keys).",
                    )

        self.generic_visit(node)


def scan_source(source: str) -> list:
    tree = ast.parse(source)
    visitor = SecurityVisitor(source.splitlines())
    visitor.visit(tree)
    return visitor.findings


def scan_file(path: Path) -> list:
    return scan_source(path.read_text(encoding="utf-8"))


def collect_python_files(path: Path) -> list:
    if path.is_file():
        return [path]
    return sorted(path.rglob("*.py"))


def build_report(results: list) -> str:
    all_findings = [(f, source) for source, findings in results for f in findings]
    high = [f for f, _ in all_findings if f["severity"] == "HIGH"]
    medium = [f for f, _ in all_findings if f["severity"] == "MEDIUM"]
    low = [f for f, _ in all_findings if f["severity"] == "LOW"]

    lines = [
        "# Python Security Code Scan Report",
        "",
        f"- **Files scanned:** {len(results)}",
        f"- **Findings:** {len(high)} HIGH, {len(medium)} MEDIUM, {len(low)} LOW",
        "",
    ]
    if all_findings:
        lines += ["| Severity | File | Line | Check | Reason |", "|---|---|---|---|---|"]
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for f, source in sorted(all_findings, key=lambda pair: order[pair[0]["severity"]]):
            reason = f["reason"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | {source} | {f['line']} | {f['check']} | {reason} |")
    else:
        lines.append("No issues found.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(results: list) -> str:
    all_findings = [f for _, findings in results for f in findings]
    payload = {
        "files_scanned": len(results),
        "summary": {
            "high": sum(1 for f in all_findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in all_findings if f["severity"] == "LOW"),
        },
        "results": [{"file": source, "findings": findings} for source, findings in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="AST-based static security scan of Python source (a file or a directory)."
    )
    parser.add_argument("--path", required=True, help="Path to a .py file or a directory to scan recursively.")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    target = Path(args.path)
    files = collect_python_files(target)

    results = []
    for f in files:
        try:
            results.append((str(f), scan_file(f)))
        except SyntaxError as exc:
            print(f"Warning: skipping {f} (syntax error: {exc})", file=sys.stderr)

    report = build_json_report(results) if args.format == "json" else build_report(results)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    all_findings = [f for _, findings in results for f in findings]
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"Scanned {len(results)} file(s): {high_count} HIGH, {medium_count} MEDIUM finding(s).")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
