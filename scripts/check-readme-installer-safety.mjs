import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const SHELL_BLOCK_PATTERN = /```(?:sh|bash|zsh)\s*\n([\s\S]*?)```/gi;

export function assertReadmeInstallerSafety(markdown) {
  const shellBlocks = [...markdown.matchAll(SHELL_BLOCK_PATTERN)].map((match) => match[1]);
  for (const shellBlock of shellBlocks) {
    if (/\binstall\.sh\b/i.test(shellBlock)) {
      throw new Error("README must not execute or download an unsigned installer shell script");
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const readmePath = process.argv[2];
  if (!readmePath) {
    throw new Error("usage: node scripts/check-readme-installer-safety.mjs <README.md>");
  }
  assertReadmeInstallerSafety(await readFile(readmePath, "utf8"));
  console.log("README installer handoff is safe");
}
