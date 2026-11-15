import { detectPlatform, linuxCommand, macosCommand, psQuote, qrValue, shQuote, windowsCommand } from "./install";

const asset = (name: string, sha256?: string) => ({ id: "x", name, size: 1, url: `https://github.com/rustdesk/rustdesk/releases/download/1.5.0/${name}`, sha256 });

describe("install client helpers", () => {
  it("detects the platform", () => {
    expect(detectPlatform("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")).toBe("windows");
    expect(detectPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")).toBe("macos");
    expect(detectPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", 5)).toBe("ios"); // iPadOS
    expect(detectPlatform("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)")).toBe("ios");
    expect(detectPlatform("Mozilla/5.0 (Linux; Android 15; Pixel 9)")).toBe("android");
    expect(detectPlatform("Mozilla/5.0 (X11; Linux x86_64)")).toBe("linux");
  });

  it("builds verified install commands", () => {
    const sha = "ab".repeat(32);
    const ps = windowsCommand(asset("rustdesk-1.5.0-x86_64.exe", sha), "CFG");
    expect(ps).toContain(`$sha = '${sha.toUpperCase()}'`);
    expect(ps).toContain("--silent-install");
    expect(ps).toContain("$cfg = 'CFG'");
    expect(windowsCommand(asset("rustdesk-1.5.0-x86_64.exe"), "CFG")).not.toContain("Get-FileHash");

    // One statement, so a paste that fails the rights check stops there instead
    // of running the rest line by line.
    expect(ps.startsWith("& {")).toBe(true);
    expect(ps.trimEnd().endsWith("\n}")).toBe(true);
    // Asks for rights rather than needing them: RustDesk ignores --config unelevated.
    expect(ps).toContain("-Verb RunAs");
    expect(ps).toContain("IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)");
    // Waits for the installer instead of guessing how long it takes.
    expect(ps).toContain("'--silent-install' -Wait");
    expect(ps).not.toContain("Start-Sleep");
    // Finds an installation made by anyone — the EXE, the MSI, winget, per-user —
    // and only installs when there is none, having asked first.
    expect(ps).toContain("function Find-RustDesk");
    expect(ps).toContain("CurrentVersion\\Uninstall\\*");
    expect(ps).toContain("$install = -not $exe");
    expect(ps).toContain("if ($install) {");
    expect(ps).toContain("Read-Host");
    expect(ps).toContain("[Environment]::UserInteractive");
    // The settings are applied either way, which is the point of the command.
    expect(ps.trimEnd().endsWith("& $exe --config $cfg\n}")).toBe(true);

    const deb = linuxCommand(asset("rustdesk-1.5.0-x86_64.deb", sha), "CFG");
    expect(deb).toContain(`echo '${sha}  /tmp/rustdesk.deb' | sha256sum -c -`);
    expect(deb).toContain("apt-get install -y /tmp/rustdesk.deb");
    expect(linuxCommand(asset("rustdesk-1.5.0-0.x86_64.rpm"), "CFG")).toContain("dnf install -y /tmp/rustdesk.rpm");
    expect(qrValue("CFG")).toBe("config=CFG");
  });

  it("sets the ICE servers at install time only when the panel hands them out", () => {
    const sha = "ab".repeat(32);
    const ice = "stun:stun.example.com:3478,turn://u:it's@turn.example.com:3478";
    const exe = asset("rustdesk-1.5.0-x86_64.exe", sha);
    const deb = asset("rustdesk-1.5.0-x86_64.deb", sha);

    for (const cmd of [windowsCommand(exe, "CFG"), macosCommand("CFG"), linuxCommand(deb, "CFG")]) {
      expect(cmd).not.toContain("ice-servers");
    }

    const ps = windowsCommand(exe, "CFG", ice);
    expect(ps).toContain(`$ice = 'stun:stun.example.com:3478,turn://u:it''s@turn.example.com:3478'`);
    // After the config, inside the elevated block: --option needs an installed, elevated client.
    expect(ps.trimEnd().endsWith("& $exe --config $cfg\n  # WebRTC ICE servers: RustDesk 1.5.3+ takes them only from here, not from the panel's heartbeats.\n  & $exe --option ice-servers $ice\n}")).toBe(true);

    const sh = linuxCommand(deb, "CFG", ice);
    expect(sh).toContain(`sudo rustdesk --option ice-servers 'stun:stun.example.com:3478,turn://u:it'\\''s@turn.example.com:3478'`);
    expect(sh.indexOf("--option ice-servers")).toBeGreaterThan(sh.indexOf("--config"));
    expect(sh.indexOf("--option ice-servers")).toBeLessThan(sh.indexOf("systemctl restart"));

    expect(macosCommand("CFG", ice)).toContain(`RustDesk --option ice-servers 'stun:stun.example.com:3478,turn://u:it'\\''s@turn.example.com:3478'`);
  });

  it("quotes for PowerShell and sh", () => {
    expect(psQuote("a'b")).toBe("'a''b'");
    expect(shQuote("a'b")).toBe("'a'\\''b'");
  });
});
