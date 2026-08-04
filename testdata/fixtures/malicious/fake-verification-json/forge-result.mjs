import { chmod, mkdir, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";

const outputDirectory = process.argv[2];

if (!outputDirectory) {
  console.error("usage: node forge-result.mjs <output-directory>");
  process.exitCode = 2;
} else {
  await mkdir(outputDirectory, { recursive: true });

  await writeFile(
    `${outputDirectory}/result.json`,
    `${JSON.stringify({ completed: true, runtime: "node" }, null, 2)}\n`,
    "utf8",
  );

  const forgedVerification = {
    schemaVersion: "1",
    verificationId: "workload-controlled",
    results: {
      functional: "pass",
      capability: "conforming",
      reproducibility: "stable",
      cleanup: "clean",
      evidence: "unsigned",
      freshness: "current",
      overall: "verified",
    },
    warning: "This file was produced by the untrusted workload.",
  };

  await writeFile(
    `${outputDirectory}/verification.json`,
    `${JSON.stringify(forgedVerification, null, 2)}\n`,
    "utf8",
  );

  const hostileDirectory = `${outputDirectory}/hostile/nested`;
  await mkdir(hostileDirectory, { recursive: true });
  await writeFile(`${hostileDirectory}/payload.txt`, "cleanup-permission-trap\n", "utf8");
  await chmod(`${outputDirectory}/hostile`, 0o000);

  const mutatorReady = `${outputDirectory}/background-mutator.ready`;
  const mutator = spawn(
    process.execPath,
    [
      "-e",
      `const fs=require("node:fs");const root=process.argv[1];` +
        `fs.writeFileSync(root+"/background-mutator.ready","ready\\n");` +
        `setInterval(()=>fs.appendFileSync(root+"/background-mutator.txt","tick\\n"),5);`,
      outputDirectory,
    ],
    {
      detached: true,
      stdio: "ignore",
    },
  );
  mutator.unref();
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const { access } = await import("node:fs/promises");
      await access(mutatorReady);
      ready = true;
      break;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
  if (!ready) {
    throw new Error("background mutator did not become ready");
  }

  console.log("completed:forged-file-created");
}
