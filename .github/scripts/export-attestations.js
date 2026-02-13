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

/** Create human-readable attestation bundle file name from asset name. */
export function bundleNameForAsset(assetPath) {
  const name = path.basename(assetPath);
  return `attestation-${name}.jsonl`;
}

/** Small command wrapper to keep command execution mockable in tests. */
export function runCmd(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", stdio: "pipe", ...opts }).trim();
}

// ----------------------------------------------------------
// Main export flow
// ----------------------------------------------------------

/**
 * Export attestation bundles for RC releases.
 *
 * Downloads attestation bundles from GitHub for:
 * - All local binary assets matching ASSET_PATTERNS
 * - The OCI image (using IMAGE_DIGEST directly, no registry lookup)
 *
 * Creates attestations-index.json with metadata for later verification.
 */
export async function runExport({ core, run = runCmd } = {}) {
  const assetsDir = process.env.ASSETS_DIR;
  const assetPatterns = process.env.ASSET_PATTERNS;
  const imageDigest = process.env.IMAGE_DIGEST;
  const imageTag = process.env.IMAGE_TAG;
  const targetRepo = process.env.TARGET_REPO;
  const outputDir = process.env.OUTPUT_DIR;
  const repository = process.env.REPOSITORY || process.env.GITHUB_REPOSITORY;

  // Validate required inputs
  if (!assetsDir || !assetPatterns || !outputDir || !repository) {
    throw new Error("Missing required env: ASSETS_DIR, ASSET_PATTERNS, OUTPUT_DIR, REPOSITORY");
  }

  if (!imageDigest || !targetRepo) {
    throw new Error("Missing required env: IMAGE_DIGEST, TARGET_REPO");
  }

  fs.mkdirSync(outputDir, { recursive: true });

  const patterns = parsePatterns(assetPatterns);
  const assets = findAssets(assetsDir, patterns);
  const attestations = [];

  core?.info(`Found ${assets.length} assets to export attestations for`);

  // Export attestations for local binary assets
  for (const asset of assets) {
    const digest = sha256File(asset);
    const bundleName = bundleNameForAsset(asset);
    const bundlePath = path.join(outputDir, bundleName);

    core?.info(`Downloading attestation for ${path.basename(asset)}...`);

    // gh attestation download writes to <digest>.jsonl
    run("gh", ["attestation", "download", asset, "--repo", repository, "--limit", "100"], { cwd: outputDir });

    // Rename from digest-based name to human-readable name
    const digestBundlePath = path.join(outputDir, `${digest}.jsonl`);
    if (fs.existsSync(digestBundlePath)) {
      fs.renameSync(digestBundlePath, bundlePath);
    } else {
      throw new Error(`Attestation bundle not found after download: ${digestBundlePath}`);
    }

    attestations.push({
      subject: path.basename(asset),
      type: "binary",
      digest,
      bundle: bundleName,
    });
  }

  // Export attestation for OCI image
  const imageRef = `${targetRepo}:${imageTag}`;
  const imageBundleName = "attestation-image.jsonl";
  const imageBundlePath = path.join(outputDir, imageBundleName);

  core?.info(`Downloading attestation for OCI image ${imageRef}...`);

  // Use oci:// prefix and @digest for precise identification
  const ociSubject = `oci://${targetRepo}@${imageDigest}`;
  run("gh", ["attestation", "download", ociSubject, "--repo", repository, "--limit", "100"], { cwd: outputDir });

  // Rename from digest-based name to human-readable name
  const imageDigestBundlePath = path.join(outputDir, `${imageDigest}.jsonl`);
  if (fs.existsSync(imageDigestBundlePath)) {
    fs.renameSync(imageDigestBundlePath, imageBundlePath);
  } else {
    throw new Error(`OCI image attestation bundle not found after download: ${imageDigestBundlePath}`);
  }

  attestations.push({
    subject: imageRef,
    type: "oci-image",
    digest: imageDigest,
    bundle: imageBundleName,
  });

  // Create attestations index
  const index = {
    version: "1",
    generated_at: new Date().toISOString(),
    rc_version: imageTag,
    image: {
      ref: imageRef,
      digest: imageDigest,
    },
    attestations,
  };

  const indexPath = path.join(outputDir, "attestations-index.json");
  fs.writeFileSync(indexPath, JSON.stringify(index, null, 2));

  core?.info(`✅ Exported ${attestations.length} attestation bundles`);
  core?.setOutput("bundle_count", String(attestations.length));
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