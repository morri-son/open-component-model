import assert from "assert";
import fs from "fs";
import os from "os";
import path from "path";
import {
  expectedReleaseAssets,
  loadAttestationIndex,
  localSubjectRef,
  parsePatternList,
  resolveBundlePath,
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
assert.strictEqual(localSubjectRef("/tmp/ocm-linux-amd64"), "file:ocm-linux-amd64");

await withTempDir(async (tmp) => {
  const assetsDir = path.join(tmp, "rc-assets");
  fs.mkdirSync(assetsDir, { recursive: true });
  const digest = `sha256:${"a".repeat(64)}`;
  fs.writeFileSync(
    path.join(assetsDir, "attestations-index.json"),
    JSON.stringify({
      entries: [{ subject: "file:ocm-linux-amd64", digest, bundle_file: "attestation-ocm-linux-amd64-aaaaaaaaaaaa.jsonl" }],
    })
  );
  const idx = loadAttestationIndex(assetsDir);
  assert(idx);
  assert.strictEqual(
    resolveBundlePath({ rcAssetsDir: assetsDir, index: idx, subjectRef: "file:ocm-linux-amd64", digest }),
    path.join(assetsDir, "attestation-ocm-linux-amd64-aaaaaaaaaaaa.jsonl")
  );
});

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
  fs.writeFileSync(path.join(assetsDir, "attestation-ocm-linux-amd64-dddddddddddd.jsonl"), "bundle-bin");
  fs.writeFileSync(path.join(assetsDir, "attestation-cli.tar-eeeeeeeeeeee.jsonl"), "bundle-tar");
  fs.writeFileSync(path.join(assetsDir, "attestation-ghcr.io-acme-cli-0.4.5-rc.1-ffffffffffff.jsonl"), "bundle-image");
  fs.writeFileSync(
    path.join(assetsDir, "attestations-index.json"),
    JSON.stringify({
      entries: [
        { subject: "file:ocm-linux-amd64", digest: binDigest, bundle_file: "attestation-ocm-linux-amd64-dddddddddddd.jsonl" },
        { subject: "file:cli.tar", digest: tarDigest, bundle_file: "attestation-cli.tar-eeeeeeeeeeee.jsonl" },
        {
          subject: "oci://ghcr.io/acme/cli:0.4.5-rc.1",
          digest: imageDigest,
          bundle_file: "attestation-ghcr.io-acme-cli-0.4.5-rc.1-ffffffffffff.jsonl",
        },
      ],
    })
  );

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
