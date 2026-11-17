# Scan reports

| File | Scan type | Tool | Scope |
|---|---|---|---|
| `sast.semgrep.json` | SAST | Semgrep (project rules in `.semgrep/`) | **Baseline** – starter code + MVP share feature (commit `0ac89d9`) |
| `sast.bandit.json` | SAST | Bandit | **Baseline** |
| `sca.pip-audit.json` | SCA (Python) | pip-audit (PyPA / OSV advisory DB) | **Baseline** `requirements.txt` |
| `sca.npm-audit.json` | SCA (Node) | npm audit (GitHub Advisory DB) | **Baseline** `notify/package-lock.json` |
| `container.trivy.json` | Container image | Trivy (vuln + secret + misconfig) | Final image – produced by the `container-scan` CI job (artifact `container.trivy.json`) |
| `container.checkov-dockerfile.json` | Container definition | Checkov (dockerfile framework) | Final `Dockerfile` |
| `iac.checkov.json` | IaC | Checkov (terraform framework) | Final `terraform/` |
| `post-remediation/*` | SAST + SCA re-scan | same tools | Final code – evidence that findings are closed |

Baseline reports are kept deliberately: `docs/findings.md` is sourced from them, and the
`post-remediation/` re-scans prove closure. CI regenerates every report on each push and
uploads them as build artifacts; the Semgrep CI job additionally runs the public
`p/python`, `p/javascript`, `p/owasp-top-ten` and `p/secrets` rulesets.
