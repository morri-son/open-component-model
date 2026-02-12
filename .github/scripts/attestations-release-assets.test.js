import assert from "assert";
import fs from "fs";
import os from "os";
import path from "path";
import {
  buildAttestationsIndex,
  digestToBundleName,
  findLocalSubjects,
  parsePatternList,
  resolveImageDigest,
  resolveOciSubjects,
  runExport,
  sha256File,
} from "./attestations-release-assets.js";

// ----------------------------------------------------------
// Test helpers
// ----------------------------------------------------------

async function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "att-rel-assets-"));
  try {
    await fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// ----------------------------------------------------------
// Helper function tests
// ----------------------------------------------------------

console.log("Testing attestations-release-assets helpers...");
assert.strictEqual(
  digestToBundleName("sha256:" + "a".repeat(64)),
  `sha256:${"a".repeat(64)}.jsonl`
);
assert.throws(() => digestToBundleName("sha1:abc"), /Invalid digest format/);
assert.strictEqual(resolveImageDigest(`sha256:${"b".repeat(64)}\n`), `sha256:${"b".repeat(64)}`);
assert.throws(() => resolveImageDigest("oops"), /Unexpected oras resolve output/);
assert.deepStrictEqual(parsePatternList('["bin/ocm-*","oci/cli.tar"]'), ["bin/ocm-*", "oci/cli.tar"]);
assert.throws(() => parsePatternList("{}"), /ASSET_PATTERNS_JSON/);

const defaultSubjects = resolveOciSubjects({ targetRepo: "ghcr.io/acme/cli", rcVersion: "0.4.5-rc.1" });
assert.deepStrictEqual(defaultSubjects, ["oci://ghcr.io/acme/cli:0.4.5-rc.1"]);
assert.deepStrictEqual(
  resolveOciSubjects({ ociSubjectsJson: '["oci://ghcr.io/acme/cli:1","oci://ghcr.io/acme/controller:1"]' }),
  ["oci://ghcr.io/acme/cli:1", "oci://ghcr.io/acme/controller:1"]
);

const idx = buildAttestationsIndex({
  imageRef: "oci://x/y:1.2.3",
  bundleNames: ["sha256:2.jsonl", "sha256:1.jsonl"],
});
assert.strictEqual(idx.image, "oci://x/y:1.2.3");
assert.strictEqual(idx.bundles[0].name, "sha256:1.jsonl");

// ----------------------------------------------------------
// runExport tests
// ----------------------------------------------------------

console.log("Testing runExport happy path...");
await withTempDir(async (tmp) => {
  const assetsRoot = path.join(tmp, "assets");
  const binDir = path.join(assetsRoot, "bin");
  const ociDir = path.join(assetsRoot, "oci");
  const bundleDir = path.join(tmp, "bundles");
  fs.mkdirSync(binDir, { recursive: true });
  fs.mkdirSync(ociDir, { recursive: true });

  const a = path.join(binDir, "ocm-linux-amd64");
  const b = path.join(binDir, "ocm-darwin-arm64");
  const c = path.join(ociDir, "cli.tar");
  fs.writeFileSync(a, "a");
  fs.writeFileSync(b, "b");
  fs.writeFileSync(c, "c");

  const imageDigest = `sha256:${"c".repeat(64)}`;

  const localSubjects = findLocalSubjects(assetsRoot, ["bin/ocm-*", "oci/cli.tar"]);
  assert.strictEqual(localSubjects.length, 3);

  const prev = { ...process.env };
  process.env.ASSETS_ROOT = assetsRoot;
  process.env.ASSET_PATTERNS_JSON = '["bin/ocm-*","oci/cli.tar"]';
  process.env.BUNDLE_DIR = bundleDir;
  process.env.TARGET_REPO = "ghcr.io/acme/cli";
  process.env.RC_VERSION = "0.4.5-rc.1";
  process.env.REPOSITORY = "acme/repo";

  // Simulate `gh attestation download` and `oras resolve` without external dependencies.
  const run = (cmd, args, opts = {}) => {
    if (cmd === "oras") return imageDigest;
    if (cmd === "gh" && args[0] === "attestation" && args[1] === "download") {
      const subject = args[2];
      const cwd = opts.cwd;
      let digest;
      if (subject.startsWith("oci://")) {
        digest = imageDigest;
      } else {
        digest = sha256File(subject);
      }
      fs.writeFileSync(path.join(cwd, `${digest}.jsonl`), "bundle");
      return "";
    }
    throw new Error(`Unexpected command ${cmd} ${args.join(" ")}`);
  };

  await runExport({ core: { setOutput: () => {} }, run });

  const files = fs.readdirSync(bundleDir).sort();
  assert(files.some((f) => f.endsWith(".jsonl")));
  assert(files.includes("attestations-index.json"));

  const parsed = JSON.parse(fs.readFileSync(path.join(bundleDir, "attestations-index.json"), "utf8"));
  assert.strictEqual(parsed.image, "oci://ghcr.io/acme/cli:0.4.5-rc.1");
  assert(parsed.bundles.length >= 4);

  // Restore process environment for isolation across tests.
  process.env = prev;
});

console.log("✅ All attestations-release-assets tests passed.");
