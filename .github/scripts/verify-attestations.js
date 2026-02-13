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
export function parsePatterns(json) {
  let parsed;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error(`Invalid ASSET_PATTERNS: ${json}`);
  }

  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.some((v) => typeof v !== "string" || !v)) {
    throw new Error(`ASSET_PATTERNS must be a non-empty JSON array of non-empty strings`);
  }

  return parsed;
}

/** Resolve local files from glob patterns. */
export function findAssets(assetsDir, patterns) {
  if (!fs.existsSync(assetsDir)) {
    throw new Error(`ASSETS_DIR does not exist: ${assetsDir}`);
  }

  const assets = new Set();
  for (const pattern of patterns) {
    const matches = fs.globSync(pattern, { cwd: assetsDir, nodir: true });
    if (matches.length === 0) {
      throw new Error(`Pattern '${pattern}' did not match any file under ${assetsDir}`);
    }
    for (const rel of matches) {
      assets.add(path.join(assetsDir, rel));
    }
  }

  return [...assets].sort();
}

/** Load attestations index from assets directory. */
export function loadIndex(assetsDir) {
  const indexPath = path.join(assetsDir, "attestations-index.json");
  if (!fs.existsSync(indexPath)) {
    throw new Error(`Attestations index not found: ${indexPath}`);
  }

  const index = JSON.parse(fs.readFileSync(indexPath, "utf8"));
  if (!index.attestations || !Array.isArray(index.attestations)) {
    throw new Error("Invalid attestations index: missing attestations array");
  }

  return index;
}

/** Find bundle path for a subject from the index. */
export function findBundle(assetsDir, index, subject) {
  const entry = index.attestations.find((a) => a.subject === subject);
  if (!entry) {
    throw new Error(`No attestation entry found for subject: ${subject}`);
  }

  const bundlePath = path.join(assetsDir, entry.bundle);
  if (!fs.existsSync(bundlePath)) {
    throw new Error(`Attestation bundle not found: ${bundlePath}`);
  }

  return bundlePath;
}

/** Small command wrapper to keep command execution mockable in tests. */
export function runCmd(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", stdio: "pipe", ...opts }).trim();
}

// ----------------------------------------------------------
// Main verification flow
// ----------------------------------------------------------

/**
 * Verify attestations from an RC release before final promotion.
 *
 * Verifies:
 * - All local binary assets matching ASSET_PATTERNS
 * - The OCI image from the index
 *
 * Fails if any verification fails.
 */
export async function runVerify({ core, run = runCmd } = {}) {
  const assetsDir = process.env.ASSETS_DIR;
  const assetPatterns = process.env.ASSET_PATTERNS;
  const imageRef = process.env.IMAGE_REF;
  const repository = process.env.REPOSITORY || process.env.GITHUB_REPOSITORY;

  // Validate required inputs
  if (!assetsDir || !assetPatterns || !repository) {
    throw new Error("Missing required env: ASSETS_DIR, ASSET_PATTERNS, REPOSITORY");
  }

  const patterns = parsePatterns(assetPatterns);
  const assets = findAssets(assetsDir, patterns);
  const index = loadIndex(assetsDir);

  core?.info(`Loaded attestations index with ${index.attestations.length} entries`);
  core?.info(`Found ${assets.length} assets to verify`);

  let verifiedCount = 0;

  // Verify attestations for local binary assets
  for (const asset of assets) {
    const subject = path.basename(asset);
    const bundle = findBundle(assetsDir, index, subject);

    core?.info(`Verifying attestation for ${subject}...`);
    run("gh", ["attestation", "verify", asset, "--repo", repository, "--bundle", bundle]);
    core?.info(`✅ ${subject} verified`);
    verifiedCount++;
  }

  // Verify attestation for OCI image using digest from index
  // Important: We use the digest from the index, not the current tag,
  // because OCI tags are mutable and may have been overwritten.
  if (index.image && index.image.ref && index.image.digest) {
    // Extract registry/repo from ref (without tag) and use digest
    const refParts = index.image.ref.split(":");
    const repoWithoutTag = refParts[0];
    const ociRefWithDigest = `oci://${repoWithoutTag}@${index.image.digest}`;
    const imageBundlePath = findBundle(assetsDir, index, index.image.ref);

    core?.info(`Verifying attestation for OCI image ${repoWithoutTag}@${index.image.digest}...`);
    run("gh", ["attestation", "verify", ociRefWithDigest, "--repo", repository, "--bundle", imageBundlePath]);
    core?.info(`✅ OCI image verified`);
    verifiedCount++;
  }

  core?.info(`✅ All ${verifiedCount} attestations verified successfully`);
  core?.setOutput("verified_count", String(verifiedCount));
  core?.setOutput("verified_image_digest", index.image?.digest || "");
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