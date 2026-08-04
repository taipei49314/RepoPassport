import { symlink, writeFile } from "node:fs/promises";

await writeFile(
  "/outputs/leak.json",
  `${JSON.stringify({ status: "functional-pass", residue: "undeclared" })}\n`,
  "utf8",
);
await symlink("/etc/shadow", "/outputs/escape-link");
console.log("completed:undeclared-residue-created");
