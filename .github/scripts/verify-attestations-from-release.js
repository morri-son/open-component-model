// @ts-check
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { execFileSync } from "child_process";

// ----------------------------------------------------------
// Helper functions
// ----------------------------------------------------------

/** Compute `sha256:<hex>` for a local file. */
export function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return `sha256:${hash.digest("hex")}`;
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

/** Resolve local files from patterns and enforce at least one hit per pattern. */
export function expectedReleaseAssets(rcAssetsDir, patterns) {
  if (!fs.existsSync(rcAssetsDir)) {
    throw new Error(`RC_ASSETS_DIR does not exist: ${rcAssetsDir}`);
  }

  const assets = new Set();
  for (const pattern of patterns) {
    const relMatches = fs.globSync(pattern, { cwd: rcAssetsDir, nodir: true });
    if (relMatches.length === 0) {
      throw new Error(`Pattern '${pattern}' did not match any file under ${rcAssetsDir}`);
    }
    for (const rel of relMatches) {
      assets.add(path.join(rcAssetsDir, rel));
    }
  }

  return [...assets].sort();
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

/** Small command wrapper to allow test-time mocking. */
export function runCmd(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", stdio: "pipe", ...opts }).trim();
}

// ----------------------------------------------------------
// Main final verification flow
// ----------------------------------------------------------

/**
 * Final verification flow:
 * - verify bundles for all configured local assets
 * - verify bundles for all configured OCI subjects
 */
export async function runVerify({ core, run = runCmd } = {}) {
  const rcAssetsDir = process.env.RC_ASSETS_DIR;
  const assetPatternsJson = process.env.ASSET_PATTERNS_JSON;
  const targetRepo = process.env.TARGET_REPO;
  const rcVersion = process.env.RC_VERSION;
  const ociSubjectsJson = process.env.OCI_SUBJECTS_JSON;
  const repository = process.env.REPOSITORY || process.env.GITHUB_REPOSITORY;

  if (!rcAssetsDir || !assetPatternsJson || !repository) {
    throw new Error("Missing required env: RC_ASSETS_DIR, ASSET_PATTERNS_JSON, REPOSITORY");
  }

  const patterns = parsePatternList(assetPatternsJson);
  const assets = expectedReleaseAssets(rcAssetsDir, patterns);
  const ociSubjects = resolveOciSubjects({ ociSubjectsJson, targetRepo, rcVersion });

  for (const asset of assets) {
    const digest = sha256File(asset);
    const bundle = path.join(rcAssetsDir, `${digest}.jsonl`);
    if (!fs.existsSync(bundle)) {
      throw new Error(`Missing attestation bundle for ${asset} (expected ${bundle})`);
    }

    run("gh", ["attestation", "verify", asset, "--repo", repository, "--bundle", bundle]);
  }

  let lastDigest = "";
  for (const imageRef of ociSubjects) {
    const digest = `${run("oras", ["resolve", imageRef.replace(/^oci:\/\//, "")])}`.trim();
    if (!/^sha256:[a-f0-9]{64}$/i.test(digest)) {
      throw new Error(`Unexpected oras resolve output: '${digest}'`);
    }

    const bundle = path.join(rcAssetsDir, `${digest}.jsonl`);
    if (!fs.existsSync(bundle)) {
      throw new Error(`Missing image attestation bundle for ${imageRef} (expected ${bundle})`);
    }

    run("gh", ["attestation", "verify", imageRef, "--repo", repository, "--bundle", bundle]);
    lastDigest = digest;
  }

  core?.setOutput("verified_assets", String(assets.length));
  core?.setOutput("verified_image_digest", lastDigest);
}

// noinspection JSUnusedGlobalSymbols
/** @param {import('@actions/github-script').AsyncFunctionArguments} args */
export default async function main({ core }) {
  try {
    await runVerify({ core });
  } catch (err) {
    core.setFailed(err.message);
  }
}
