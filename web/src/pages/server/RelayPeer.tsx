import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";

import type { Schemas } from "@/api/client";
import { Mono } from "@/components";
import { formatRustdeskId } from "@/lib/format";

type DeviceRef = Schemas["RelayDeviceRef"];

/**
 * Which device labels to show for a relay peer: the first max of devices and
 * how many matching devices are left (devices_total counts the ones the API
 * did not send too). Labels are a hint: devices behind one NAT share an IP.
 */
export function relayPeerLabels(devices: readonly DeviceRef[], total: number, max = 2): { shown: DeviceRef[]; more: number } {
  const shown = devices.slice(0, max);
  return { shown, more: Math.max(total, devices.length) - shown.length };
}

/** How recent a heartbeat must be for its address to label a relay peer (as on the server). */
export const DEVICE_IP_FRESHNESS_MS = 10 * 60 * 1000;

/**
 * The address of an hbbr peer or a stored IP, comparable across spellings:
 * "1.2.3.4:5", "[::ffff:1.2.3.4]:5" and "1.2.3.4" all give "1.2.3.4".
 */
export function peerAddress(peer: string): string {
  let host = peer.trim().toLowerCase();
  const v6 = /^\[(.+)\]:\d+$/.exec(host);
  if (v6) host = v6[1]!;
  else if (/^[^:]+:\d+$/.test(host)) host = host.slice(0, host.lastIndexOf(":"));
  if (host.startsWith("::ffff:") && host.includes(".")) host = host.slice("::ffff:".length);
  return host;
}

/** hbbr "elapsed" seconds as "5m 12s" / "2h 3m". */
export function formatElapsed(s: number): string {
  if (s >= 3600) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

/**
 * A relay peer (ip:port) with the devices recently seen at its IP. Each label
 * links to the device (its drawer shows the RustDesk ID).
 */
export function RelayPeer({ peer, devices, total }: { peer: string; devices: readonly DeviceRef[]; total: number }) {
  const { t } = useTranslation();
  const { shown, more } = relayPeerLabels(devices, total);
  return (
    <span className="inline-flex flex-wrap items-baseline gap-x-1">
      <Mono>{peer}</Mono>
      {shown.length > 0 && (
        <span className="text-muted-foreground" title={t("relays.live.devicesHint")}>
          (
          {shown.map((d, i) => (
            <span key={d.id}>
              {i > 0 && ", "}
              <Link
                to="/devices"
                search={{ device: d.id }}
                className="underline-offset-2 hover:text-foreground hover:underline"
                aria-label={`${d.label} (${formatRustdeskId(d.rustdesk_id)})`}
              >
                {d.label}
              </Link>
            </span>
          ))}
          {more > 0 && ` +${more}`})
        </span>
      )}
    </span>
  );
}
