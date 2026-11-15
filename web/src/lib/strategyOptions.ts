/**
 * Options RustDesk 1.5.3 refuses to take from heartbeat strategies
 * (BLOCKED_CONFIG_OPTIONS in src/hbbs_http/sync.rs, rustdesk/rustdesk#16696;
 * names from libs/base/src/config/keys.rs). Older clients still apply them;
 * 1.5.3 and later keep their own value and only log the rejected names.
 */
export const STRATEGY_OPTIONS_IGNORED_SINCE_1_5_3: readonly string[] = [
  // Server endpoints and trust
  "custom-rendezvous-server",
  "rendezvous-servers",
  "api-server",
  "relay-server",
  "key",
  "ice-servers",
  // Transport security
  "allow-insecure-tls-fallback",
  "allow-websocket",
  "websocket-port",
  // Authentication and credentials
  "2fa",
  "bot",
  "preset-address-book-password",
  "enable-trusted-devices",
  "trusted-device-expiration-days",
  // Deployment and address book metadata
  "preset-address-book-name",
  "preset-address-book-tag",
  "preset-address-book-alias",
  "preset-address-book-note",
  "preset-device-name",
  "preset-device-username",
  "preset-note",
  // Recording location and service state
  "windows-service-video-save-directory",
  "stop-service",
  "reg_recovery",
];

/** The keys of a strategy that RustDesk 1.5.3 and later ignore, sorted. */
export function ignoredStrategyKeys(options: Record<string, string> | null | undefined): string[] {
  return Object.keys(options ?? {})
    .filter((k) => STRATEGY_OPTIONS_IGNORED_SINCE_1_5_3.includes(k))
    .sort();
}
