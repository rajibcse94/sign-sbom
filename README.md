# LedgerProve — sign-sbom GitHub Action

Cryptographically sign your SBOM, append it to a tamper-evident hash chain, and get a public verification URL — all in one CI step.

```yaml
- name: Sign SBOM with LedgerProve
  uses: ledgerprove/sign-sbom@v1
  with:
    api-key: ${{ secrets.LEDGERPROVE_API_KEY }}
    sbom-file: ./sbom.json
```

## What it does

1. Reads your SBOM file (CycloneDX or SPDX, JSON).
2. Hashes it with SHA-256.
3. POSTs the hash + metadata to LedgerProve's API.
4. The API signs your record with **ECDSA-P521** using a private key in **AWS KMS** (the key never leaves AWS).
5. Your record is appended to a per-org **SHA-512 hash chain** — tampering with any record breaks all subsequent ones.
6. An **RFC 3161 timestamp** is requested from a public TSA so anyone can prove when the record was signed.
7. The Action sets `verification-url` as an output for use by later steps (PR comments, release notes, etc.).

Anyone can verify the signed SBOM at the verification URL with a single OpenSSL command. No account required.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | ✅ | — | Your LedgerProve API key (`lp_live_…`). Generate at https://ledgerprove.com/dashboard. Store as a repo or org secret. |
| `sbom-file` | ✅ | — | Path to the SBOM JSON file. Generate it in an earlier step with `syft`, `cyclonedx-cli`, or your tool of choice. |
| `repo-id` | — | `${{ github.repository }}` | Repository identifier under which to record this build. |
| `commit-hash` | — | `${{ github.sha }}` | The commit SHA to record. |
| `build-status` | — | `PASS` | `PASS`, `FAIL`, or `WARN`. Use `FAIL` to record a failed build (e.g. tests failed, vulns found). |
| `cve-count` | — | `0` | Number of CVEs found in this build, if known. |
| `api-url` | — | `https://api.ledgerprove.com` | Override the LedgerProve API URL. Only set this for self-hosted/staging. |

## Outputs

| Output | Description |
|--------|-------------|
| `verification-id` | Public verification ID (24-char hex) |
| `verification-url` | Public URL anyone can use to verify the SBOM |
| `signature-algorithm` | Always `ECDSA-P521-SHA512` |
| `chain-index` | Position of this record in your organisation's chain |
| `record-hash` | SHA-512 of the signed record |
| `timestamped` | `true` if an RFC 3161 timestamp was attached |

## Full example — sign every build, post the verify URL on PRs

```yaml
name: Build & Sign SBOM
on: [push, pull_request]

jobs:
  build-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # 1. Generate an SBOM with Syft (works for any language / lockfile)
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          format: cyclonedx-json
          output-file: sbom.json

      # 2. Sign and chain it with LedgerProve
      - name: Sign with LedgerProve
        id: ledgerprove
        uses: ledgerprove/sign-sbom@v1
        with:
          api-key: ${{ secrets.LEDGERPROVE_API_KEY }}
          sbom-file: ./sbom.json

      # 3. Comment the verification URL on the PR
      - name: Comment verify URL on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '🛡 SBOM signed: ${{ steps.ledgerprove.outputs.verification-url }}'
            })
```

## Setting up the API key

1. Sign in at https://ledgerprove.com/login (GitHub or Google).
2. Click **Generate API key** in your dashboard.
3. Copy the `lp_live_…` value (shown once).
4. In your GitHub repo (or org): **Settings → Secrets and variables → Actions → New repository secret**
   - Name: `LEDGERPROVE_API_KEY`
   - Value: paste your key
5. Use `${{ secrets.LEDGERPROVE_API_KEY }}` in your workflow.

## Free plan limits

- **1 repository** with unlimited builds.
- ECDSA-P521 signing on every build.
- Public verification links forever.

For more repos, CVE alerts, SBOM diff and team accounts, see https://ledgerprove.com/pricing.

## Verifying a signed SBOM yourself

Anyone can verify a record without a LedgerProve account:

```bash
# 1. Fetch the public record
curl -s https://api.ledgerprove.com/verify/<verification-id>

# 2. Download our public key
curl -sO https://api.ledgerprove.com/.well-known/public-key.pem

# 3. (Optional) Verify the RFC 3161 timestamp with OpenSSL
openssl ts -reply -in token.tsr -text
```

## License

ISC. Source: https://github.com/ledgerprove/sign-sbom

## Issues / questions

- General: https://github.com/ledgerprove/sign-sbom/issues
- Email: hello@ledgerprove.com
