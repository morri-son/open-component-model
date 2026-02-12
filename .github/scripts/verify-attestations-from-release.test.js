import assert from "assert";
import fs from "fs";
import os from "os";
import path from "path";
import {
  expectedReleaseAssets,
  parsePatternList,
  resolveOciSubjects,
  runVerify,
  sha256File,
} from "./verify-attestations-from-release.js";

// ----------------------------------------------------------
// Test helpers
// ----------------------------------------------------------

async function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "verify-att-"));
  try {
    await fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ----------------------------------------------------------
// expectedReleaseAssets tests
// ----------------------------------------------------------

console.log("Testing verify-attestations-from-release helpers...");
await withTempDir((tmp) => {
  assert.throws(() => expectedReleaseAssets(path.join(tmp, "missing"), ["ocm-*"]), /does not exist/);

  const assets = path.join(tmp, "assets");
  fs.mkdirSync(assets, { recursive: true });
  fs.writeFileSync(path.join(assets, "ocm-linux-amd64"), "x");
  assert.throws(() => expectedReleaseAssets(assets, ["cli.tar"]), /did not match any file/);

  fs.writeFileSync(path.join(assets, "cli.tar"), "y");
  const list = expectedReleaseAssets(assets, ["ocm-*", "cli.tar"]);
  assert.strictEqual(list.length, 2);
});

assert.deepStrictEqual(parsePatternList('["ocm-*","cli.tar"]'), ["ocm-*", "cli.tar"]);
assert.throws(() => parsePatternList("[]"), /ASSET_PATTERNS_JSON/);
assert.deepStrictEqual(
  resolveOciSubjects({ ociSubjectsJson: '["oci://ghcr.io/acme/cli:1","oci://ghcr.io/acme/controller:1"]' }),
  ["oci://ghcr.io/acme/cli:1", "oci://ghcr.io/acme/controller:1"]
);

// ----------------------------------------------------------
// runVerify tests
// ----------------------------------------------------------

console.log("Testing runVerify happy path...");
await withTempDir(async (tmp) => {
  const assetsDir = path.join(tmp, "rc-assets");
  fs.mkdirSync(assetsDir, { recursive: true });

  const bin = path.join(assetsDir, "ocm-linux-amd64");
  const tar = path.join(assetsDir, "cli.tar");
  fs.writeFileSync(bin, "bin");
  fs.writeFileSync(tar, "tar");

  const imageDigest = `sha256:${"d".repeat(64)}`;
  const binDigest = sha256File(bin);
  const tarDigest = sha256File(tar);
  fs.writeFileSync(path.join(assetsDir, `${binDigest}.jsonl`), "bundle-bin");
  fs.writeFileSync(path.join(assetsDir, `${tarDigest}.jsonl`), "bundle-tar");
  fs.writeFileSync(path.join(assetsDir, `${imageDigest}.jsonl`), "bundle-image");

  const calls = [];
  const run = (cmd, args) => {
    calls.push([cmd, ...args]);
    if (cmd === "oras") return imageDigest;
    if (cmd === "gh") return "";
    throw new Error(`Unexpected command: ${cmd}`);
  };

  const prev = { ...process.env };
  process.env.RC_ASSETS_DIR = assetsDir;
  process.env.ASSET_PATTERNS_JSON = '["ocm-*","cli.tar"]';
  process.env.TARGET_REPO = "ghcr.io/acme/cli";
  process.env.RC_VERSION = "0.4.5-rc.1";
  process.env.REPOSITORY = "acme/repo";

  // Simulate verify and resolve commands without calling external tooling.
  await runVerify({ core: { setOutput: () => {} }, run });
  assert(calls.some((c) => c[0] === "gh" && c.includes("verify")));
  assert(calls.some((c) => c[0] === "oras" && c[1] === "resolve"));

  // Restore process environment for isolation across tests.
  process.env = prev;
});

console.log("Testing runVerify failure (missing bundle)...");
await withTempDir(async (tmp) => {
  const assetsDir = path.join(tmp, "rc-assets");
  fs.mkdirSync(assetsDir, { recursive: true });

  const bin = path.join(assetsDir, "ocm-linux-amd64");
  const tar = path.join(assetsDir, "cli.tar");
  fs.writeFileSync(bin, "bin");
  fs.writeFileSync(tar, "tar");

  // only one bundle, others missing
  fs.writeFileSync(path.join(assetsDir, `${sha256File(bin)}.jsonl`), "bundle-bin");

  const prev = { ...process.env };
  process.env.RC_ASSETS_DIR = assetsDir;
  process.env.ASSET_PATTERNS_JSON = '["ocm-*","cli.tar"]';
  process.env.TARGET_REPO = "ghcr.io/acme/cli";
  process.env.RC_VERSION = "0.4.5-rc.1";
  process.env.REPOSITORY = "acme/repo";

  await assert.rejects(
    () => runVerify({ run: () => `sha256:${"e".repeat(64)}` }),
    /Missing attestation bundle/
  );

  // Restore process environment for isolation across tests.
  process.env = prev;
});

console.log("✅ All verify-attestations-from-release tests passed.");
