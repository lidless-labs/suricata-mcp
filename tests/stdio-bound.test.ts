import { PassThrough } from "node:stream";
import { afterEach, expect, it, vi } from "vitest";
import { once } from "node:events";

const fake = vi.hoisted(() => ({ stdin: null as any, stdout: null as any, transport: null as any }));
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@modelcontextprotocol/sdk/server/stdio.js")>();
  return { ...actual, StdioServerTransport: class extends actual.StdioServerTransport {
    constructor(...args: ConstructorParameters<typeof actual.StdioServerTransport>) {
      // Keep production's public SDK options, but connect to in-memory streams.
      super(fake.stdin, fake.stdout, args[2]);
      fake.transport = this;
    }
  } };
});
afterEach(async () => { await fake.transport?.close(); fake.stdin?.destroy(); fake.stdout?.destroy(); });
it("accepts normal stdio requests and closes when an unfinished message exceeds 10 MiB", async () => {
  fake.stdin = new PassThrough();
  fake.stdout = new PassThrough();
  await import("../src/index.js");
  const errors: Error[] = [];
  const originalError = fake.transport.onerror;
  fake.transport.onerror = (error: Error) => { errors.push(error); originalError?.(error); };
  const reply = once(fake.stdout, "data");
  fake.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "fake", version: "1" } } }) + "\n");
  expect(JSON.parse((await reply)[0].toString()).id).toBe(1);
  let closed = false;
  const originalClose = fake.transport.onclose;
  fake.transport.onclose = () => { closed = true; originalClose?.(); };
  const chunk = Buffer.alloc(1024 * 1024, " ");
  for (let i = 0; i < 10; i++) fake.stdin.write(chunk);
  expect(errors).toHaveLength(0);
  expect(closed).toBe(false);
  fake.stdin.write(Buffer.from(" "));
  expect(errors.at(-1)?.message).toContain("maximum size");
  expect(closed).toBe(true);
});
