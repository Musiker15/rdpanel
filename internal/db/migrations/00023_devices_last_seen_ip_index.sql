-- +goose Up

-- /relays/sessions and the relay usage tables label hbbr peers with the
-- devices recently seen at the peer's address (devices.last_seen_ip), every
-- 10 s while one of those views is open.
CREATE INDEX ix_devices_last_seen_ip ON devices (last_seen_ip) WHERE last_seen_ip IS NOT NULL;

-- +goose Down
DROP INDEX ix_devices_last_seen_ip;
