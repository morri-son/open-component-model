import assert from "assert";
import { deriveLatestRcMetadata, parseReleaseBranch } from "./release-utils.js";

// ----------------------------------------------------------
// parseReleaseBranch tests
// ----------------------------------------------------------
assert.strictEqual(parseReleaseBranch("releases/v0.1"), "0.1");
assert.throws(() => parseReleaseBranch("main"), /Invalid branch format/);
assert.throws(() => parseReleaseBranch("releases/v1.0"), /Invalid branch format/);

// ----------------------------------------------------------
// deriveLatestRcMetadata tests
// ----------------------------------------------------------
const withRc = deriveLatestRcMetadata("cli/v0.3.1-rc.4", "cli");
assert.deepStrictEqual(withRc, {
  latestRcTag: "cli/v0.3.1-rc.4",
  latestRcVersion: "0.3.1-rc.4",
  latestPromotionVersion: "0.3.1",
  latestPromotionTag: "cli/v0.3.1",
  latestRcExists: "true",
});

const withoutRc = deriveLatestRcMetadata("", "cli");
assert.deepStrictEqual(withoutRc, {
  latestRcTag: "",
  latestRcVersion: "",
  latestPromotionVersion: "",
  latestPromotionTag: "",
  latestRcExists: "false",
});

const nestedComponent = deriveLatestRcMetadata("kubernetes/controller/v0.8.2-rc.1", "kubernetes/controller");
assert.deepStrictEqual(nestedComponent, {
  latestRcTag: "kubernetes/controller/v0.8.2-rc.1",
  latestRcVersion: "0.8.2-rc.1",
  latestPromotionVersion: "0.8.2",
  latestPromotionTag: "kubernetes/controller/v0.8.2",
  latestRcExists: "true",
});

console.log("✅ All resolve-latest-rc tests passed.");
