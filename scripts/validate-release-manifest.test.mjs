import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

import { validateReleaseManifest } from "./validate-release-manifest.mjs";

const fixtureUrl = new URL("./fixtures/collector-release-v0.1.1.json", import.meta.url);
const validManifest = JSON.parse(await readFile(fixtureUrl, "utf8"));

assert.doesNotThrow(() => validateReleaseManifest(validManifest));

for (const [label, mutate] of [
  ["draft release", (manifest) => (manifest.source.draft = true)],
  ["prerelease", (manifest) => (manifest.source.prerelease = true)],
  ["unstable version", (manifest) => (manifest.version = "0.1.2-rc.1")],
  ["wrong repository", (manifest) => (manifest.source.repository = "evil/collector")],
  ["wrong release URL", (manifest) => (manifest.releaseUrl = "https://evil.test/release")],
  [
    "wrong asset URL",
    (manifest) => (manifest.artifacts.linux.amd64.url = "https://evil.test/archive.tar.gz"),
  ],
  [
    "missing Linux signature",
    (manifest) => {
      delete manifest.artifacts.linux.amd64.signatureUrl;
    },
  ],
  [
    "invalid checksum",
    (manifest) => (manifest.verification.checksumsSha256 = "not-a-checksum"),
  ],
  ["unexpected platform", (manifest) => (manifest.artifacts.windows = {})],
]) {
  const candidate = structuredClone(validManifest);
  mutate(candidate);
  assert.throws(
    () => validateReleaseManifest(candidate),
    undefined,
    `manifest validator accepted ${label}`,
  );
}

console.log("collector release manifest contract tests passed");
