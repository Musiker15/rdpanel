import { describe, expect, it } from "vitest";

import { formatElapsed, peerAddress, relayPeerLabels } from "@/pages/server/RelayPeer";

const dev = (id: number, label: string) => ({ id, rustdesk_id: String(100000000 + id), label });

describe("relayPeerLabels", () => {
  it("shows nothing without devices", () => {
    expect(relayPeerLabels([], 0)).toEqual({ shown: [], more: 0 });
  });

  it("shows up to two labels and counts the rest, including devices the API left out", () => {
    expect(relayPeerLabels([dev(1, "Office laptop")], 1).shown.map((d) => d.label)).toEqual(["Office laptop"]);
    const four = [dev(1, "A"), dev(2, "B"), dev(3, "C"), dev(4, "D")];
    expect(relayPeerLabels(four, 4)).toEqual({ shown: four.slice(0, 2), more: 2 });
    expect(relayPeerLabels(four, 40).more).toBe(38);
  });
});

describe("formatElapsed", () => {
  it("formats minutes and hours", () => {
    expect(formatElapsed(75)).toBe("1m 15s");
    expect(formatElapsed(3720)).toBe("1h 2m");
  });
});

describe("peerAddress", () => {
  it("strips the port and unmaps IPv4-mapped IPv6", () => {
    expect(peerAddress("192.0.2.10:51234")).toBe("192.0.2.10");
    expect(peerAddress("[2001:DB8::1]:6000")).toBe("2001:db8::1");
    expect(peerAddress("[::ffff:192.0.2.10]:5555")).toBe("192.0.2.10");
    expect(peerAddress("192.0.2.10")).toBe("192.0.2.10");
    expect(peerAddress("2001:db8::1")).toBe("2001:db8::1");
  });
});
