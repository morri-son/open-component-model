// @ts-check
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { execFileSync } from "child_process";

// ----------------------------------------------------------
// Helper functions
// ----------------------------------------------------------

/** Convert a `sha256:<hex>` digest to the GitHub attestation bundle filename. */
export function digestToBundleName(digest) {
  if (!/^sha256:[a-f0-9]{64}$/i.test(`${digest || ""}`)) {
    throw new Error(`Invalid digest format: ${digest}`);
  }
  return `${digest}.jsonl`;
}

/** Validate and normalize `oras resolve` output. */
export function resolveImageDigest(output) {
  const digest = `${output || ""}`.trim();
  if (!/^sha256:[a-f0-9]{64}$/i.test(digest)) {
    throw new Error(`Unexpected oras resolve output: '${output}'`);
  }
  return digest;
}

/** Parse JSON array input and validate string entries. */
export function parseJsonStringArray(json, varName) {
  let parsed;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error(`Invalid ${varName}: ${json}`);
  }

  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.some((v) => typeof v !== "string" || !v)) {
    throw new Error(`${varName} must be a non-empty JSON array of non-empty strings`);
  }

  return parsed;
}

/** Backward-compatible alias for tests and existing call sites. */
export function parsePatternList(json) {
  return parseJsonStringArray(json, "ASSET_PATTERNS_JSON");
}

/** Resolve local subjects from glob patterns and enforce at least one hit per pattern. */
export function resolveLocalSubjects(assetsRoot, patterns) {
  if (!fs.existsSync(assetsRoot)) {
    throw new Error(`ASSETS_ROOT does not exist: ${assetsRoot}`);
  }

  const subjects = new Set();
  for (const pattern of patterns) {
    const relMatches = fs.globSync(pattern, { cwd: assetsRoot, nodir: true });
    if (relMatches.length === 0) {
      throw new Error(`Pattern '${pattern}' did not match any file under ${assetsRoot}`);
    }
    for (const rel of relMatches) {
      subjects.add(path.join(assetsRoot, rel));
    }
  }

  return [...subjects].sort();
}

/** Backward-compatible alias for tests and existing call sites. */
export function findLocalSubjects(assetsRoot, patterns) {
  return resolveLocalSubjects(assetsRoot, patterns);
}

/** Resolve OCI subjects from JSON, or fallback to TARGET_REPO/RC_VERSION. */
export function resolveOciSubjects({ ociSubjectsJson, targetRepo, rcVersion }) {
  if (ociSubjectsJson) {
    return parseJsonStringArray(ociSubjectsJson, "OCI_SUBJECTS_JSON");
  }
  if (!targetRepo || !rcVersion) {
    throw new Error("Missing TARGET_REPO/RC_VERSION and OCI_SUBJECTS_JSON not provided");
  }
  return [`oci://${targetRepo}:${rcVersion}`];
}

/** Build a stable, machine-readable index for uploaded attestation bundles. */
export function buildAttestationsIndex({ imageRef, bundleNames }) {
  return {
    generated_at: new Date().toISOString(),
    image: imageRef,
    bundles: [...bundleNames].sort().map((name) => ({
      name,
      digest: name.replace(/\.jsonl$/, ""),
    })),
  };
}

/** Compute `sha256:<hex>` for a local file. */
export function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return `sha256:${hash.digest("hex")}`;
}

/** Small command wrapper to keep command execution mockable in tests. */
export function runCmd(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", stdio: "pipe", ...opts }).trim();
}

// ----------------------------------------------------------
// Main RC export flow
// ----------------------------------------------------------

/**
 * RC export flow:
 * - download attestation bundles for matching local assets
 * - download attestation bundles for OCI subjects
 * - create `attestations-index.json`
 */
export async function runExport({ core, run = runCmd } = {}) {
  const assetsRoot = process.env.ASSETS_ROOT;
  const assetPatternsJson = process.env.ASSET_PATTERNS_JSON;
  const bundleDir = process.env.BUNDLE_DIR;
  const targetRepo = process.env.TARGET_REPO;
  const rcVersion = process.env.RC_VERSION;
  const ociSubjectsJson = process.env.OCI_SUBJECTS_JSON;
  const repository = process.env.REPOSITORY || process.env.GITHUB_REPOSITORY;

  if (!assetsRoot || !assetPatternsJson || !bundleDir || !repository) {
    throw new Error("Missing required env: ASSETS_ROOT, ASSET_PATTERNS_JSON, BUNDLE_DIR, REPOSITORY");
  }

  fs.mkdirSync(bundleDir, { recursive: true });
  const patterns = parsePatternList(assetPatternsJson);
  const localSubjects = findLocalSubjects(assetsRoot, patterns);
  const ociSubjects = resolveOciSubjects({ ociSubjectsJson, targetRepo, rcVersion });
  const bundleNames = [];

  for (const subject of localSubjects) {
    const digest = sha256File(subject);
    const bundleName = digestToBundleName(digest);
    run("gh", ["attestation", "download", subject, "--repo", repository, "--limit", "100"], { cwd: bundleDir });
    if (!fs.existsSync(path.join(bundleDir, bundleName))) {
      throw new Error(`Missing expected bundle after download: ${path.join(bundleDir, bundleName)}`);
    }
    bundleNames.push(bundleName);
  }

  for (const ociSubject of ociSubjects) {
    const digest = resolveImageDigest(run("oras", ["resolve", ociSubject.replace(/^oci:\/\//, "")]));
    const bundleName = digestToBundleName(digest);
    run("gh", ["attestation", "download", ociSubject, "--repo", repository, "--limit", "100"], { cwd: bundleDir });
    if (!fs.existsSync(path.join(bundleDir, bundleName))) {
      throw new Error(`Missing expected image bundle after download: ${path.join(bundleDir, bundleName)}`);
    }
    bundleNames.push(bundleName);
  }

  const indexPath = path.join(bundleDir, "attestations-index.json");
  fs.writeFileSync(indexPath, JSON.stringify(buildAttestationsIndex({ imageRef: ociSubjects[0], bundleNames }), null, 2));

  core?.setOutput("bundle_count", String(bundleNames.length));
  core?.setOutput("index_path", indexPath);
}

// noinspection JSUnusedGlobalSymbols
/** @param {import('@actions/github-script').AsyncFunctionArguments} args */
export default async function main({ core }) {
  try {
    await runExport({ core });
  } catch (err) {
    core.setFailed(err.message);
  }
}
