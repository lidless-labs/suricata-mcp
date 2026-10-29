import { EventEmitter } from "node:events";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as net from "node:net";
import { registerThreatIntelTools } from "../src/tools/threatintel.js";
import { registerSocketTools } from "../src/socket/client.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SuricataConfig } from "../src/config.js";

vi.mock("node:net", () => ({ createConnection: vi.fn() }));
const canary = "fake-boundary-canary";
const config = { mispUrl: "https://intel.invalid/private", mispApiKey: canary,
  thehiveUrl: "https://cases.invalid/private", thehiveApiKey: canary,
  unixSocket: "/fake/suricata.sock", allowMutation: true } as SuricataConfig;
function handlers(register: typeof registerThreatIntelTools) {
  const tools = new Map<string, (args: any) => Promise<any>>();
  const server = { tool: (...args: any[]) => tools.set(args[0], args.at(-1)) } as unknown as McpServer;
  register(server, config);
  return tools;
}
const search = () => handlers(registerThreatIntelTools).get("misp_search_ioc")!({ value: "192.0.2.1" });
const stats = () => handlers(registerSocketTools).get("suricata_iface_stat")!({});
function fakeResponse(chunks: Uint8Array[], status = 200, length?: string) {
  let index = 0;
  const read = vi.fn(async () => index < chunks.length ? { done: false, value: chunks[index++] } : { done: true });
  const cancel = vi.fn(() => new Promise<void>(() => {})); // Cleanup must never await a hostile producer.
  const releaseLock = vi.fn();
  const getReader = vi.fn(() => ({ read, cancel, releaseLock }));
  const text = vi.fn(async () => Buffer.concat(chunks).toString());
  const headers = new Headers(length === undefined ? {} : { "content-length": length });
  if (status >= 300 && status < 400) headers.set("location", `https://redirect.invalid/private?key=${canary}`);
  const response = { status, statusText: canary, type: "basic", headers,
    body: { getReader, cancel }, text } as unknown as Response;
  vi.stubGlobal("fetch", vi.fn(async () => response));
  return { read, cancel, releaseLock, getReader, text };
}
function expectPrivate(result: any) {
  expect(result.isError).toBe(true);
  expect(result.content[0].text).not.toContain(canary);
  expect(result.content[0].text).not.toContain("https://");
  expect(result.content[0].text).not.toContain("private");
}
class FakeSocket extends EventEmitter {
  write = vi.fn();
  destroy = vi.fn(() => this);
  setTimeout = vi.fn(() => this);
}
let socket: FakeSocket;
beforeEach(() => {
  socket = new FakeSocket();
  vi.mocked(net.createConnection).mockImplementation(((_path: string, onConnect?: () => void) => {
    if (onConnect) queueMicrotask(onConnect);
    return socket;
  }) as any);
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.clearAllMocks(); });
function expectSocketClean() {
  expect(socket.destroy).toHaveBeenCalledOnce();
  for (const event of ["connect", "data", "end", "error", "timeout", "close"]) expect(socket.listenerCount(event)).toBe(0);
  expect(vi.getTimerCount()).toBe(0);
}

describe("HTTP upstream boundary", () => {
  it.each([400, 500, 302])("does not read HTTP %i bodies or echo redirects/secrets", async status => {
    const fake = fakeResponse([Buffer.from(canary)], status);
    const result = await search();
    expectPrivate(result);
    expect(fake.text).not.toHaveBeenCalled();
    expect(fake.read).not.toHaveBeenCalled();
    expect(fake.cancel).toHaveBeenCalledOnce();
    const options = vi.mocked(fetch).mock.calls[0][1]!;
    expect(options.redirect).toBe("manual");
    expect(options.signal!.aborted).toBe(true);
  });
  it("rejects oversized Content-Length before acquiring a body reader", async () => {
    const fake = fakeResponse([Buffer.from('{}')], 200, "1048577");
    expectPrivate(await search());
    expect(fake.getReader).not.toHaveBeenCalled();
    expect(fake.cancel).toHaveBeenCalledOnce();
  });
  it.each(["invalid", "-1", "99999999999999999999"])("refuses invalid or excessive declared length %s", async length => {
    const fake = fakeResponse([Buffer.from('{}')], 200, length);
    expectPrivate(await search());
    expect(fake.read).not.toHaveBeenCalled();
    expect(fake.cancel).toHaveBeenCalledOnce();
  });
  it("rejects unknown-length overflow before another read and cancels promptly", async () => {
    const fake = fakeResponse([Buffer.alloc(1048576, 32), Buffer.from('x'), Buffer.from(canary)]);
    expectPrivate(await search());
    expect(fake.read).toHaveBeenCalledTimes(2);
    expect(fake.cancel).toHaveBeenCalledOnce();
    expect(fake.releaseLock).toHaveBeenCalledOnce();
  });
  it.each(["", "\ufeff"])("decodes fragmented multibyte JSON with BOM %j and preserves small response shapes", async bom => {
    const bytes = Buffer.from(bom + '{"response":{"Attribute":[{"id":"1","value":"café😀"}]}}');
    fakeResponse(Array.from(bytes, byte => Uint8Array.of(byte)));
    const result = await search();
    expect(result.isError).toBeUndefined();
    expect(JSON.parse(result.content[0].text).attributes[0].value).toBe("café😀");
  });
  it("accepts an exactly-budgeted response with known length", async () => {
    fakeResponse([Buffer.from('{}' + ' '.repeat(1048574))], 200, "1048576");
    expect((await search()).isError).toBeUndefined();
  });
  it("cancels and releases a real fake-source stream after a body deadline", async () => {
    vi.useFakeTimers();
    const cancel = vi.fn(() => new Promise<void>(() => {}));
    const body = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(Buffer.from('{')); }, cancel,
    });
    vi.stubGlobal("fetch", vi.fn(async () => new Response(body)));
    const pending = search();
    await vi.advanceTimersByTimeAsync(30000);
    expectPrivate(await pending);
    expect(cancel).toHaveBeenCalledOnce();
    expect(body.locked).toBe(false);
    expect(vi.getTimerCount()).toBe(0);
  });
  it("sanitizes stream failures and rejected cancellation", async () => {
    const fake = fakeResponse([]);
    fake.read.mockRejectedValue(new Error(canary));
    fake.cancel.mockRejectedValue(new Error(canary));
    expectPrivate(await search());
    expect(fake.releaseLock).toHaveBeenCalledOnce();
  });
  it("bounds empty fragment floods", async () => {
    const fake = fakeResponse(Array.from({ length: 4097 }, () => new Uint8Array()));
    expectPrivate(await search());
    expect(fake.read).toHaveBeenCalledTimes(4097);
    expect(fake.cancel).toHaveBeenCalledOnce();
  });
  it.each(["headers", "body"])("enforces its whole-request deadline while stalled at %s", async phase => {
    vi.useFakeTimers();
    const fake = fakeResponse([]);
    if (phase === "headers") vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    else fake.read.mockImplementation(() => new Promise(() => {}));
    const pending = search();
    await vi.advanceTimersByTimeAsync(30000);
    const result = await pending;
    expectPrivate(result);
    expect(result.content[0].text).toContain("timed out");
    expect(vi.mocked(fetch).mock.calls[0][1]!.signal!.aborted).toBe(true);
    if (phase === "body") expect(fake.cancel).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });
  it("redacts transport errors containing credentials or URLs", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error(`https://intel.invalid/private?key=${canary}`); }));
    expectPrivate(await search());
  });
  it.each(["thehive_create_case", "thehive_create_alert"])("applies the same unread failure boundary to %s", async name => {
    const fake = fakeResponse([Buffer.from(canary)], 500);
    const result = await handlers(registerThreatIntelTools).get(name)!({ confirm: true, title: "example", description: "example" });
    expectPrivate(result);
    expect(fake.text).not.toHaveBeenCalled();
    expect(fake.read).not.toHaveBeenCalled();
  });
});

describe("socket upstream boundary", () => {
  it("counts raw fragmented bytes and decodes UTF-8 once at completion", async () => {
    vi.useFakeTimers();
    const pending = stats();
    for (const byte of Buffer.from('café😀')) socket.emit("data", Buffer.from([byte]));
    socket.emit("end");
    expect(JSON.parse((await pending).content[0].text).response).toBe("café😀");
    expectSocketClean();
  });
  it("accepts the exact raw byte budget and clears both socket deadlines", async () => {
    vi.useFakeTimers();
    const pending = stats();
    socket.emit("connect");
    socket.emit("data", Buffer.alloc(1048576, 97));
    socket.emit("end");
    expect((await pending).isError).toBeUndefined();
    expect(socket.write).toHaveBeenCalledWith('{"command":"iface-stat"}');
    expectSocketClean();
  });
  it.each(["overflow", "empty fragments", "timeout", "idle timeout", "error", "close"])("terminates and cleans up on %s", async failure => {
    vi.useFakeTimers();
    const pending = stats();
    if (failure === "overflow") {
      socket.emit("data", Buffer.from("é".repeat(524288)));
      socket.emit("data", Buffer.from('x'));
    } else if (failure === "empty fragments") {
      for (let i = 0; i < 4097; i++) socket.emit("data", Buffer.alloc(0));
    } else if (failure === "timeout") {
      // An active peer must not extend the total command deadline.
      await vi.advanceTimersByTimeAsync(9000);
      socket.emit("data", Buffer.from("keepalive"));
      await vi.advanceTimersByTimeAsync(1000);
    } else if (failure === "idle timeout") socket.emit("timeout");
    else if (failure === "error") socket.emit("error", new Error(canary));
    else socket.emit("close");
    const result = await pending;
    expectPrivate(result);
    socket.emit("end"); // No second resolution or retained terminal listeners.
    expectSocketClean();
  });
});
