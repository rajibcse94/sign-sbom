// ============================================================
// LedgerProve — sign-sbom GitHub Action
//
// Reads a CycloneDX or SPDX SBOM JSON file, hashes it, and POSTs
// it to LedgerProve's signing API. The API signs with ECDSA-P521
// (key in AWS KMS), appends to a per-org hash chain, and returns a
// public verification URL that anyone can use to verify the build.
//
// All work happens in <3 seconds. Action outputs verification-url
// for use by later steps (e.g. PR comments, release notes).
// ============================================================

import * as core from '@actions/core';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { spawnSync } from 'child_process';

interface SignResponse {
  success?: boolean;
  message?: string;
  error?: string;
  data?: {
    id: string;
    verificationId: string;
    verificationUrl: string;
    timestamp: string;
    signatureAlgorithm: string;
    chain: { index: number; previousHash: string; recordHash: string };
    timestamping: { standard: string; source?: string | null };
  };
}

function detectSbomFormat(json: unknown): 'cyclonedx' | 'spdx' {
  const o = json as Record<string, unknown>;
  if (typeof o.bomFormat === 'string' && (o.bomFormat as string).toLowerCase() === 'cyclonedx') return 'cyclonedx';
  if (typeof o.spdxVersion === 'string') return 'spdx';
  // Best-effort default
  return 'cyclonedx';
}

function countPackages(json: unknown): number {
  const o = json as Record<string, unknown>;
  // CycloneDX
  if (Array.isArray(o.components)) return o.components.length;
  // SPDX
  if (Array.isArray(o.packages)) return o.packages.length;
  return 0;
}

// Extract a flat package list from an SBOM for the API's diff feature.
// Keeps name + version + ecosystem only — everything else (licenses,
// hashes, supplier metadata) stays out of the API payload. CycloneDX and
// SPDX have completely different schemas; we normalise to one shape.
//
// Returned list is capped at 5000 entries to match the API limit. Larger
// SBOMs send the first 5000 — the diff will be partial in that pathological
// case, but very few real projects exceed it.
interface SbomPkg { name: string; version?: string; ecosystem?: string }
function extractPackages(json: unknown): SbomPkg[] {
  const out: SbomPkg[] = [];
  const o = json as Record<string, unknown>;
  // CycloneDX: components: [{ name, version, purl }]
  if (Array.isArray(o.components)) {
    for (const c of o.components as Array<Record<string, unknown>>) {
      const name = typeof c.name === 'string' ? c.name : null;
      if (!name) continue;
      const version = typeof c.version === 'string' ? c.version : undefined;
      // Ecosystem is encoded in the purl: pkg:npm/foo@1.2.3 → ecosystem=npm
      let ecosystem: string | undefined;
      if (typeof c.purl === 'string') {
        const m = /^pkg:([a-z0-9.+-]+)\//i.exec(c.purl);
        if (m) ecosystem = m[1]!.toLowerCase();
      }
      out.push(version || ecosystem ? { name, version, ecosystem } : { name });
      if (out.length >= 5000) break;
    }
  } else if (Array.isArray(o.packages)) {
    // SPDX: packages: [{ name, versionInfo, externalRefs: [{ referenceType: 'purl', referenceLocator }] }]
    for (const p of o.packages as Array<Record<string, unknown>>) {
      const name = typeof p.name === 'string' ? p.name : null;
      if (!name) continue;
      const version = typeof p.versionInfo === 'string' ? p.versionInfo : undefined;
      let ecosystem: string | undefined;
      const refs = Array.isArray(p.externalRefs) ? (p.externalRefs as Array<Record<string, unknown>>) : [];
      for (const r of refs) {
        if (r.referenceType === 'purl' && typeof r.referenceLocator === 'string') {
          const m = /^pkg:([a-z0-9.+-]+)\//i.exec(r.referenceLocator);
          if (m) { ecosystem = m[1]!.toLowerCase(); break; }
        }
      }
      out.push(version || ecosystem ? { name, version, ecosystem } : { name });
      if (out.length >= 5000) break;
    }
  }
  return out;
}

// If the user didn't provide an SBOM file, install Syft and generate one.
// Syft is the de-facto standard SBOM generator and works for npm, PyPI, Go,
// Maven, RubyGems, crates, and most other ecosystems out of the box.
function ensureSbomFile(provided: string): string {
  if (provided) {
    if (!fs.existsSync(provided)) {
      throw new Error(`SBOM file not found: ${provided}`);
    }
    return provided;
  }
  if (process.platform !== 'linux') {
    throw new Error(
      'Auto-SBOM generation only supports Linux runners (ubuntu-latest). ' +
      'On other runners, generate the SBOM yourself in a previous step and pass `sbom-file:` explicitly.',
    );
  }
  const workspace = process.env.GITHUB_WORKSPACE || process.cwd();
  const syftDir = '/tmp/lp-syft';
  const syftBin = `${syftDir}/syft`;
  const outputFile = '/tmp/lp-auto-sbom.cyclonedx.json';

  if (!fs.existsSync(syftBin)) {
    // Pin the Syft version we install. NEVER `curl … main | sh` — that pulls
    // whatever HEAD is at install time, with no checksum, which is a supply
    // chain risk (Anchore's repo could be tampered with, the install script
    // could be changed mid-CI). Pinning to a tagged release file means:
    //   - Reproducible builds: same Syft binary every run
    //   - Anchore-signed release artifacts checked at the pinned URL
    //   - Easy upgrade via a single bump in this file
    const SYFT_VERSION = 'v1.18.1';
    core.info(`Installing Syft ${SYFT_VERSION} (one-time, ~5s)…`);
    fs.mkdirSync(syftDir, { recursive: true });
    const installScriptUrl = `https://raw.githubusercontent.com/anchore/syft/${SYFT_VERSION}/install.sh`;
    const install = spawnSync(
      'sh',
      ['-c', `curl -sSfL --retry 3 --retry-delay 2 ${installScriptUrl} | sh -s -- -b ${syftDir} ${SYFT_VERSION}`],
      { stdio: 'inherit' },
    );
    if (install.status !== 0) throw new Error(`Failed to install Syft ${SYFT_VERSION}`);
  }

  core.info(`Generating CycloneDX SBOM from ${workspace}…`);
  const gen = spawnSync(syftBin, [`dir:${workspace}`, '-o', `cyclonedx-json=${outputFile}`, '-q'], { stdio: 'inherit' });
  if (gen.status !== 0) throw new Error('Failed to generate SBOM with Syft');
  if (!fs.existsSync(outputFile)) throw new Error(`Syft did not write the expected file: ${outputFile}`);

  return outputFile;
}

function postJson(urlStr: string, headers: Record<string, string>, body: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request({
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: (u.pathname || '/') + (u.search || ''),
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body).toString(),
        ...headers,
      },
      timeout: 30000,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode ?? 0,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('API request timed out')); });
    req.write(body);
    req.end();
  });
}

async function run(): Promise<void> {
  try {
    // ---- Read inputs ----
    const apiKey = core.getInput('api-key', { required: true });
    // Mask the key in EVERY downstream log line — including stack traces from
    // unrelated failures (Syft install, fs read, JSON parse). Must happen
    // BEFORE any other operation that might throw.
    core.setSecret(apiKey);
    // sbom-file is now optional — auto-generate if missing
    const providedSbomFile = core.getInput('sbom-file');
    const repoId = core.getInput('repo-id') || process.env.GITHUB_REPOSITORY || '';
    const commitHash = core.getInput('commit-hash') || process.env.GITHUB_SHA || '';
    const buildStatus = (core.getInput('build-status') || 'PASS').toUpperCase();
    // Coerce safely: parseInt on garbage returns NaN which JSON-serializes
    // to null, confusing the API. Default to 0 on any non-numeric input.
    const cveRaw = parseInt(core.getInput('cve-count') || '0', 10);
    const cveCount = Number.isFinite(cveRaw) && cveRaw >= 0 ? cveRaw : 0;
    const apiUrl = (core.getInput('api-url') || 'https://api.ledgerprove.com').replace(/\/$/, '');

    if (!repoId) throw new Error('repo-id not provided and GITHUB_REPOSITORY is empty');
    if (!commitHash) throw new Error('commit-hash not provided and GITHUB_SHA is empty');

    // ---- Resolve the SBOM file (auto-generate via Syft if not provided) ----
    const sbomFile = ensureSbomFile(providedSbomFile);

    // ---- Read and hash the SBOM ----
    const sbomBytes = fs.readFileSync(sbomFile);
    const sbomHash = 'sha256:' + crypto.createHash('sha256').update(sbomBytes).digest('hex');

    let sbomJson: unknown = {};
    try { sbomJson = JSON.parse(sbomBytes.toString('utf8')); }
    catch { /* not JSON — that's fine, we still hash and submit */ }
    const sbomFormat = detectSbomFormat(sbomJson);
    const packageCount = countPackages(sbomJson);
    // packages: extracted flat list (name + version + ecosystem) so the
    // LedgerProve API can compute build-to-build diffs server-side.
    // Server treats this as optional — older action versions still work.
    const packages = extractPackages(sbomJson);

    core.info(`SBOM file:    ${sbomFile} (${sbomBytes.length} bytes)`);
    core.info(`Format:       ${sbomFormat}`);
    core.info(`Packages:     ${packageCount}`);
    core.info(`Hash:         ${sbomHash}`);
    core.info(`Repository:   ${repoId}`);
    core.info(`Commit:       ${commitHash.slice(0, 12)}…`);
    core.info('');

    // ---- POST to LedgerProve ----
    const payload = JSON.stringify({
      repoId,
      commitHash,
      sbomHash,
      packageCount,
      cveCount,
      buildStatus,
      sbomFormat,
      // Optional — Starter+ plans use this for SBOM diff. Lower plans store
      // it harmlessly but can't query the diff endpoint.
      packages,
    });

    core.info(`Submitting to ${apiUrl}/api/v1/sbom …`);
    const res = await postJson(`${apiUrl}/api/v1/sbom`, {
      'Authorization': `Bearer ${apiKey}`,
    }, payload);

    let parsed: SignResponse;
    try { parsed = JSON.parse(res.body) as SignResponse; }
    catch { throw new Error(`API returned non-JSON (status ${res.status}): ${res.body.slice(0, 500)}`); }

    if (res.status !== 201) {
      const errMsg = parsed.error || parsed.message || `HTTP ${res.status}`;
      // Mask the API key for safety, then bail
      core.setSecret(apiKey);
      throw new Error(`LedgerProve API rejected the request: ${errMsg}`);
    }

    if (!parsed.data) throw new Error(`Unexpected API response: ${res.body.slice(0, 500)}`);
    const d = parsed.data;

    // ---- Set outputs ----
    core.setOutput('verification-id', d.verificationId);
    core.setOutput('verification-url', d.verificationUrl);
    core.setOutput('signature-algorithm', d.signatureAlgorithm);
    core.setOutput('chain-index', d.chain.index);
    core.setOutput('record-hash', d.chain.recordHash);
    core.setOutput('timestamped', d.timestamping?.source ? 'true' : 'false');

    // ---- Console summary (visible in Action logs) ----
    core.info('');
    core.info('✓ SBOM signed and chained');
    core.info(`  chain index #${d.chain.index}`);
    core.info(`  recordHash  ${d.chain.recordHash.slice(0, 24)}…`);
    core.info(`  algorithm   ${d.signatureAlgorithm}`);
    core.info(`  timestamp   ${d.timestamping?.source ? 'RFC 3161 (' + d.timestamping.source + ')' : 'TSA unavailable — chain still valid'}`);
    core.info('');
    core.info(`  Verify URL: ${d.verificationUrl}`);

    // ---- Step Summary (rich markdown shown in the GitHub Actions UI) ----
    await core.summary
      .addHeading('🛡 LedgerProve — SBOM signed and chained', 2)
      .addTable([
        [{ data: 'Field', header: true }, { data: 'Value', header: true }],
        ['Repository', repoId],
        ['Commit', `\`${commitHash.slice(0, 12)}\``],
        ['SBOM hash', `\`${sbomHash}\``],
        ['Packages', String(packageCount)],
        ['Build status', buildStatus],
        ['Chain index', `#${d.chain.index}`],
        ['Algorithm', d.signatureAlgorithm],
        ['RFC 3161 timestamp', d.timestamping?.source ? '✓ ' + d.timestamping.source : '— (TSA unavailable)'],
      ])
      .addRaw('\n')
      .addLink(`Verify this build publicly →`, d.verificationUrl)
      .addRaw('\n\n')
      .addRaw('_Anyone can verify this SBOM was not modified since signing. No account required._')
      .write();
  } catch (err) {
    const msg = (err as Error).message;
    // Emit empty outputs so downstream `if: always()` steps that read them
    // get explicit empty strings rather than undefined.
    core.setOutput('verification-id', '');
    core.setOutput('verification-url', '');
    core.setOutput('signature-algorithm', '');
    core.setOutput('chain-index', '');
    core.setOutput('record-hash', '');
    core.setOutput('timestamped', 'false');
    core.setFailed(msg);
  }
}

void run();
