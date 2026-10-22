import { describe, it, expect } from "vitest";

// Temporary: proves CI goes red on a failing test (#15). Removed before merge.
describe("ci fail-closed demo", () => {
  it("fails on purpose", () => {
    expect(1).toBe(2);
  });
});
