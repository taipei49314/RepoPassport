import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const [inputPath, outputPath] = process.argv.slice(2);

if (!inputPath || !outputPath) {
  console.error("usage: node cli.mjs <input> <output>");
  process.exitCode = 2;
} else {
  const message = (await readFile(inputPath, "utf8")).trim();
  const result = {
    message,
    bytes: Buffer.byteLength(message, "utf8"),
    runtime: "node",
  };

  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  console.log(JSON.stringify(result));
}
