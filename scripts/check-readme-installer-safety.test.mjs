import assert from "node:assert/strict";

import { assertReadmeInstallerSafety } from "./check-readme-installer-safety.mjs";

assert.doesNotThrow(() =>
  assertReadmeInstallerSafety(
    "The maintainer helper is named `scripts/install.sh`, but it is not an official handoff.",
  ),
);

for (const [label, shellBlock] of [
  ["curl pipe", "curl -fsSL https://example.test/install.sh | bash"],
  ["wget pipe", "wget -qO- https://example.test/install.sh | sh"],
  ["process substitution", "bash <(curl -fsSL https://example.test/install.sh)"],
  ["redirected process substitution", "zsh < <(wget -qO- https://example.test/install.sh)"],
]) {
  assert.throws(
    () => assertReadmeInstallerSafety(`\`\`\`sh\n${shellBlock}\n\`\`\``),
    undefined,
    `README safety validator accepted ${label}`,
  );
}

console.log("README installer safety tests passed");
