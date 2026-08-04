import { createServer } from "node:http";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

function parseArguments(argv) {
  const result = { output: "", port: 8080 };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--output" && index + 1 < argv.length) {
      result.output = argv[++index];
    } else if (argv[index] === "--port" && index + 1 < argv.length) {
      result.port = Number.parseInt(argv[++index], 10);
    } else {
      throw new Error(`unsupported argument: ${argv[index]}`);
    }
  }
  if (!result.output || !Number.isInteger(result.port) || result.port < 1 || result.port > 65535) {
    throw new Error("valid --output and --port arguments are required");
  }
  return result;
}

function sendJSON(response, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.length),
    "x-repopass-runtime": "node",
  });
  response.end(body);
}

const options = parseArguments(process.argv.slice(2));
const server = createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/health") {
    sendJSON(response, 200, { status: "ok" });
    return;
  }
  if (request.method !== "POST" || request.url !== "/echo") {
    sendJSON(response, 404, { error: "not-found" });
    return;
  }

  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 1024 * 1024) {
      sendJSON(response, 413, { error: "request-too-large" });
      return;
    }
    chunks.push(chunk);
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    sendJSON(response, 400, { error: "invalid-json" });
    return;
  }

  const result = { received: payload, runtime: "node" };
  await mkdir(dirname(options.output), { recursive: true });
  await writeFile(options.output, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  sendJSON(response, 200, result);
});

server.listen(options.port, "127.0.0.1", () => {
  process.stdout.write(`listening:127.0.0.1:${options.port}\n`);
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    server.close((error) => {
      process.exitCode = error ? 1 : 0;
    });
  });
}
