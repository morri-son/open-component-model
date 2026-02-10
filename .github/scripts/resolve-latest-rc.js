// @ts-check
import { execSync } from "child_process";
import { deriveLatestRcMetadata, parseReleaseBranch } from "./release-utils.js";

/**
 * Resolve latest RC tag metadata for a release branch + component.
 *
 * @param {string} branch
 * @param {string} componentPath
 * @returns {{ latestRcTag: string, latestRcVersion: string, latestPromotionVersion: string, latestPromotionTag: string, latestRcExists: string }}
 */
export function resolveLatestRc(branch, componentPath) {
  const basePrefix = parseReleaseBranch(branch);

  if (!componentPath) {
    throw new Error("componentPath is required");
  }

  const tagPattern = `${componentPath}/v${basePrefix}.*-rc.*`;
  const latestRcTag = execSync(`git tag --list '${tagPattern}' | sort -V | tail -n1`).toString().trim();
  return deriveLatestRcMetadata(latestRcTag, componentPath);
}

// --------------------------
// GitHub Actions entrypoint
// --------------------------
// noinspection JSUnusedGlobalSymbols
/** @param {import('@actions/github-script').AsyncFunctionArguments} args */
export default async function resolveLatestRcAction({ core }) {
  const branch = process.env.BRANCH;
  const componentPath = process.env.COMPONENT_PATH;

  if (!branch || !componentPath) {
    core.setFailed("Missing BRANCH or COMPONENT_PATH");
    return;
  }

  try {
    const { latestRcTag, latestRcVersion, latestPromotionVersion, latestPromotionTag, latestRcExists } = resolveLatestRc(branch, componentPath);

    core.setOutput("latest_rc_tag", latestRcTag);
    core.setOutput("latest_rc_version", latestRcVersion);
    core.setOutput("latest_promotion_version", latestPromotionVersion);
    core.setOutput("latest_promotion_tag", latestPromotionTag);
    core.setOutput("latest_rc_exists", latestRcExists);

    await core.summary
      .addHeading("📦 Latest RC Resolution")
      .addTable([
        [{ data: "Field", header: true }, { data: "Value", header: true }],
        ["Release Branch", branch],
        ["Component Path", componentPath],
        ["Latest RC Exists", latestRcExists],
        ["Latest RC Tag", latestRcTag || "(none)"],
        ["Latest RC Version", latestRcVersion || "(none)"],
        ["Latest Promotion Version", latestPromotionVersion || "(none)"],
        ["Latest Promotion Tag", latestPromotionTag || "(none)"],
      ])
      .write();
  } catch (error) {
    core.setFailed(error.message);
  }
}
