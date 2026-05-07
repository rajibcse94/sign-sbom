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
    const sbomFile = core.getInput('sbom-file', { required: true });
    const repoId = core.getInput('repo-id') || process.env.GITHUB_REPOSITORY || '';
    const commitHash = core.getInput('commit-hash') || process.env.GITHUB_SHA || '';
    const buildStatus = (core.getInput('build-status') || 'PASS').toUpperCase();
    const cveCount = parseInt(core.getInput('cve-count') || '0', 10);
    const apiUrl = (core.getInput('api-url') || 'https://api.ledgerprove.com').replace(/\/$/, '');

    if (!repoId) throw new Error('repo-id not provided and GITHUB_REPOSITORY is empty');
    if (!commitHash) throw new Error('commit-hash not provided and GITHUB_SHA is empty');
    if (!fs.existsSync(sbomFile)) throw new Error(`SBOM file not found: ${sbomFile}`);

    // ---- Read and hash the SBOM ----
    const sbomBytes = fs.readFileSync(sbomFile);
    const sbomHash = 'sha256:' + crypto.createHash('sha256').update(sbomBytes).digest('hex');

    let sbomJson: unknown = {};
    try { sbomJson = JSON.parse(sbomBytes.toString('utf8')); }
    catch { /* not JSON — that's fine, we still hash and submit */ }
    const sbomFormat = detectSbomFormat(sbomJson);
    const packageCount = countPackages(sbomJson);

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
    core.setFailed(msg);
  }
}

void run();
