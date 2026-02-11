// @ts-check

/**
 * Parse release branches of form releases/v0.X
 * Keep centralized to ensure consistent parsing and error handling across scripts.
 * @param {string} branch
 * @returns {string} base prefix (e.g. 0.1)
 */
export function parseReleaseBranch(branch) {
  const match = /^releases\/v(0\.\d+)$/.exec(branch || "");
  if (!match) {
    throw new Error(`Invalid branch format: ${branch}`);
  }
  return match[1];
}

/**
 * Derive latest RC metadata from latest RC tag and component path.
 * @param {string} latestRcTag
 * @param {string} componentPath
 */
export function deriveLatestRcMetadata(latestRcTag, componentPath) {
  const latestRcVersion = latestRcTag ? latestRcTag.replace(`${componentPath}/v`, "") : "";
  const latestPromotionVersion = latestRcVersion ? latestRcVersion.replace(/-rc\.\d+$/, "") : "";
  const latestPromotionTag = latestRcTag
    ? `${componentPath}/v${latestPromotionVersion}`
    : "";

  return { latestRcTag, latestRcVersion, latestPromotionVersion, latestPromotionTag };
}
