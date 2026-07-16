import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const STABLE_VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const TRUST_ROOT_STATUSES = new Set(["current", "next", "previous"]);

export function validateReleaseManifest(input) {
  const manifest = requireObject(input, "manifest");
  requireExactKeys(
    manifest,
    [
      "artifacts",
      "install",
      "publishedAt",
      "releaseUrl",
      "schemaVersion",
      "source",
      "trust",
      "verification",
      "version",
    ],
    "manifest",
  );

  if (manifest.schemaVersion !== 1) {
    throw new Error("manifest schemaVersion must be 1");
  }
  const version = requireString(manifest.version, "manifest.version");
  if (!STABLE_VERSION_PATTERN.test(version)) {
    throw new Error("manifest version must be a stable semantic version");
  }

  const tag = `v${version}`;
  const releaseBase = `https://github.com/mitoriq/collector/releases/download/${tag}`;
  requireEqual(
    manifest.releaseUrl,
    `https://github.com/mitoriq/collector/releases/tag/${tag}`,
    "manifest.releaseUrl",
  );
  if (Number.isNaN(Date.parse(requireString(manifest.publishedAt, "manifest.publishedAt")))) {
    throw new Error("manifest publishedAt must be an ISO timestamp");
  }

  validateSource(manifest.source);
  validateArtifacts(manifest.artifacts, version, releaseBase);
  validateVerification(manifest.verification, releaseBase);
  validateTrust(manifest.trust);
  validateInstall(manifest.install, tag);

  return manifest;
}

function validateSource(input) {
  const source = requireObject(input, "manifest.source");
  requireExactKeys(source, ["draft", "prerelease", "repository"], "manifest.source");
  requireEqual(source.repository, "mitoriq/collector", "manifest.source.repository");
  requireEqual(source.draft, false, "manifest.source.draft");
  requireEqual(source.prerelease, false, "manifest.source.prerelease");
}

function validateArtifacts(input, version, releaseBase) {
  const artifacts = requireObject(input, "manifest.artifacts");
  requireExactKeys(artifacts, ["linux", "macos"], "manifest.artifacts");

  for (const platform of ["linux", "macos"]) {
    const platformArtifacts = requireObject(
      artifacts[platform],
      `manifest.artifacts.${platform}`,
    );
    requireExactKeys(platformArtifacts, ["amd64", "arm64"], `manifest.artifacts.${platform}`);
    const releaseOs = platform === "macos" ? "darwin" : "linux";

    for (const arch of ["amd64", "arm64"]) {
      const label = `manifest.artifacts.${platform}.${arch}`;
      const artifact = requireObject(platformArtifacts[arch], label);
      const expectedKeys =
        platform === "linux" ? ["name", "sha256", "signatureUrl", "url"] : ["name", "sha256", "url"];
      requireExactKeys(artifact, expectedKeys, label);

      const expectedName = `mitoriq-collector_${version}_${releaseOs}_${arch}.tar.gz`;
      requireEqual(artifact.name, expectedName, `${label}.name`);
      requireEqual(artifact.url, `${releaseBase}/${expectedName}`, `${label}.url`);
      requireSha256(artifact.sha256, `${label}.sha256`);

      if (platform === "linux") {
        requireEqual(
          artifact.signatureUrl,
          `${releaseBase}/mitoriq-collector_linux_${arch}.sig`,
          `${label}.signatureUrl`,
        );
      }
    }
  }
}

function validateVerification(input, releaseBase) {
  const verification = requireObject(input, "manifest.verification");
  requireExactKeys(
    verification,
    ["checksumsSha256", "checksumsSignatureUrl", "checksumsUrl"],
    "manifest.verification",
  );
  requireSha256(verification.checksumsSha256, "manifest.verification.checksumsSha256");
  requireEqual(
    verification.checksumsUrl,
    `${releaseBase}/checksums.txt`,
    "manifest.verification.checksumsUrl",
  );
  requireEqual(
    verification.checksumsSignatureUrl,
    `${releaseBase}/checksums.txt.sig`,
    "manifest.verification.checksumsSignatureUrl",
  );
}

function validateTrust(input) {
  const trust = requireObject(input, "manifest.trust");
  requireExactKeys(
    trust,
    [
      "cosignAlgorithm",
      "cosignPublicKeySha256",
      "cosignPublicKeyUrl",
      "cosignPublicKeys",
      "macosTeamId",
    ],
    "manifest.trust",
  );
  requireEqual(trust.cosignAlgorithm, "ECDSA P-256 / SHA-256", "manifest.trust.cosignAlgorithm");
  requireEqual(
    trust.cosignPublicKeyUrl,
    "https://mitoriq.vercel.app/.well-known/collector-release-key.pem",
    "manifest.trust.cosignPublicKeyUrl",
  );
  if (!/^[A-Z0-9]{10}$/.test(requireString(trust.macosTeamId, "manifest.trust.macosTeamId"))) {
    throw new Error("manifest.trust.macosTeamId must be a 10-character Apple Team ID");
  }

  if (!Array.isArray(trust.cosignPublicKeys) || trust.cosignPublicKeys.length === 0) {
    throw new Error("manifest.trust.cosignPublicKeys must not be empty");
  }
  const fingerprints = new Set();
  let currentKey;

  for (const [index, rawTrustRoot] of trust.cosignPublicKeys.entries()) {
    const label = `manifest.trust.cosignPublicKeys[${index}]`;
    const trustRoot = requireObject(rawTrustRoot, label);
    requireExactKeys(trustRoot, ["sha256", "status", "url"], label);
    const sha256 = requireSha256(trustRoot.sha256, `${label}.sha256`);
    if (!TRUST_ROOT_STATUSES.has(trustRoot.status)) {
      throw new Error(`${label}.status is invalid`);
    }
    if (fingerprints.has(sha256)) {
      throw new Error("manifest trust-root fingerprints must be unique");
    }
    fingerprints.add(sha256);
    requireEqual(
      trustRoot.url,
      `https://mitoriq.vercel.app/.well-known/collector-release-keys/${sha256}.pem`,
      `${label}.url`,
    );
    if (trustRoot.status === "current") {
      if (currentKey) {
        throw new Error("manifest must publish exactly one current trust root");
      }
      currentKey = trustRoot;
    }
  }

  if (!currentKey) {
    throw new Error("manifest must publish exactly one current trust root");
  }
  requireEqual(
    trust.cosignPublicKeySha256,
    currentKey.sha256,
    "manifest.trust.cosignPublicKeySha256",
  );
}

function validateInstall(input, tag) {
  const install = requireObject(input, "manifest.install");
  requireExactKeys(install, ["linux", "macos"], "manifest.install");
  const linux = requireObject(install.linux, "manifest.install.linux");
  const macos = requireObject(install.macos, "manifest.install.macos");
  requireExactKeys(linux, ["installerUrl", "repositoryUrl"], "manifest.install.linux");
  requireExactKeys(macos, ["command"], "manifest.install.macos");
  requireEqual(
    linux.installerUrl,
    `https://raw.githubusercontent.com/mitoriq/collector/${tag}/scripts/install.sh`,
    "manifest.install.linux.installerUrl",
  );
  requireEqual(
    linux.repositoryUrl,
    `https://github.com/mitoriq/collector/tree/${tag}`,
    "manifest.install.linux.repositoryUrl",
  );
  requireEqual(
    macos.command,
    "brew install --cask mitoriq/tap/mitoriq-collector",
    "manifest.install.macos.command",
  );
}

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function requireSha256(value, label) {
  const sha256 = requireString(value, label);
  if (!SHA256_PATTERN.test(sha256)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return sha256;
}

function requireEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} does not match the public release contract`);
  }
}

function requireExactKeys(value, expectedKeys, label) {
  const actualKeys = Object.keys(value).sort();
  const sortedExpectedKeys = [...expectedKeys].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(sortedExpectedKeys)) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const manifestPath = process.argv[2];
  if (!manifestPath) {
    throw new Error("usage: node scripts/validate-release-manifest.mjs <manifest.json>");
  }
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  validateReleaseManifest(manifest);
  console.log("collector release manifest is valid");
}
