import { markConnectIntent, takeConnectIntent } from "./connectIntent";

describe("connect intent", () => {
  beforeEach(() => localStorage.clear());

  it("lets the panel's own link connect once", () => {
    markConnectIntent("123456789", 1000);
    expect(takeConnectIntent("123456789", 2000)).toBe(true);
    expect(takeConnectIntent("123456789", 2000)).toBe(false); // used up
  });

  it("refuses an outside link: no intent, another id or an old one", () => {
    expect(takeConnectIntent("123456789")).toBe(false);
    markConnectIntent("111", 1000);
    expect(takeConnectIntent("222", 2000)).toBe(false);
    markConnectIntent("111", 1000);
    expect(takeConnectIntent("111", 1000 + 61_000)).toBe(false);
  });
});
