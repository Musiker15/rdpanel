package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bropines/rdpanel/internal/crypto"
	"github.com/bropines/rdpanel/internal/logs"
)

const rootfs = "../../deploy/rootfs"

// TestDeployScriptsParse runs `sh -n` over the image's shell scripts.
func TestDeployScriptsParse(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	var scripts []string
	for _, pat := range []string{"usr/libexec/rdpanel/*", "usr/local/bin/*", "etc/s6-overlay/s6-rc.d/*/run", "etc/s6-overlay/s6-rc.d/*/up"} {
		m, _ := filepath.Glob(filepath.Join(rootfs, pat))
		scripts = append(scripts, m...)
	}
	if len(scripts) < 10 {
		t.Fatalf("found only %d scripts", len(scripts))
	}
	for _, s := range scripts {
		if out, err := exec.Command(sh, "-n", s).CombinedOutput(); err != nil {
			t.Errorf("sh -n %s: %v\n%s", s, err, out)
		}
	}
}

// TestHBBSAuthzEnv sources the helper the hbbs run script uses to point hbbs
// at /internal/hbbs/authorize and checks what it exports for typical
// RDPANEL_LISTEN forms, operator overrides and the off switches.
func TestHBBSAuthzEnv(t *testing.T) {
	// The image runs busybox sh; check every POSIX shell at hand.
	var shells [][]string
	for _, sh := range [][]string{{"sh"}, {"dash"}, {"bash", "--posix"}, {"busybox", "sh"}} {
		if p, err := exec.LookPath(sh[0]); err == nil {
			shells = append(shells, append([]string{p}, sh[1:]...))
		}
	}
	if len(shells) == 0 {
		t.Skip("no sh")
	}
	script, err := filepath.Abs(filepath.Join(rootfs, "usr/libexec/rdpanel/hbbs-authz-env"))
	if err != nil {
		t.Fatal(err)
	}
	run, err := os.ReadFile(filepath.Join(rootfs, "etc/s6-overlay/s6-rc.d/hbbs/run"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(run), "\n. /usr/libexec/rdpanel/hbbs-authz-env\n") {
		t.Fatal("the hbbs run script does not source hbbs-authz-env")
	}
	const (
		def    = "http://127.0.0.1:21114/internal/hbbs/authorize"
		defKey = "/data/panel/hbbs-authz.key"
	)
	for _, c := range []struct {
		env      map[string]string
		url, key string
	}{
		{nil, def, defKey},
		{map[string]string{"RDPANEL_LISTEN": ":21114"}, def, defKey},
		{map[string]string{"RDPANEL_LISTEN": "0.0.0.0:21114"}, def, defKey},
		{map[string]string{"RDPANEL_LISTEN": "127.0.0.1:31114"}, "http://127.0.0.1:31114/internal/hbbs/authorize", defKey},
		{map[string]string{"RDPANEL_LISTEN": "[::1]:21114"}, "http://[::1]:21114/internal/hbbs/authorize", defKey},
		{map[string]string{"RDPANEL_LISTEN": "[::]:8080"}, "http://127.0.0.1:8080/internal/hbbs/authorize", defKey},
		{map[string]string{"RDPANEL_LISTEN": "localhost:21114"}, def, defKey},
		{map[string]string{"RDPANEL_LISTEN": "10.0.0.5:21114"}, "unset", defKey},
		{map[string]string{"RDPANEL_LISTEN": "127.0.0.1"}, "unset", defKey},
		{map[string]string{"RDPANEL_DATA_DIR": "/srv/panel"}, def, "/srv/panel/hbbs-authz.key"},
		{map[string]string{"RDPANEL_HBBS_AUTHZ_SECRET_FILE": "/run/secrets/authz", "RDPANEL_DATA_DIR": "/srv/panel"}, def, "/run/secrets/authz"},
		{map[string]string{"AUTHZ_URL": "http://127.0.0.1:9/x", "AUTHZ_SECRET_FILE": "/etc/authz"}, "http://127.0.0.1:9/x", "/etc/authz"},
		{map[string]string{"AUTHZ_URL": "http://127.0.0.1:9/x", "RDPANEL_LISTEN": "10.0.0.5:1"}, "http://127.0.0.1:9/x", defKey},
		{map[string]string{"RDPANEL_HBBS_AUTHZ": "true"}, def, defKey},
		{map[string]string{"RDPANEL_HBBS_AUTHZ": "false"}, "unset", "unset"},
		{map[string]string{"RDPANEL_HBBS_AUTHZ": "0"}, "unset", "unset"},
		{map[string]string{"RDPANEL_HBBS_AUTHZ": "False"}, "unset", "unset"},
		{map[string]string{"RDPANEL_MODE": "agent"}, "unset", "unset"},
	} {
		for _, sh := range shells {
			// The values must be exported (seen by a child process), and the
			// helper's own names must not leak into hbbs' environment.
			args := append(append([]string{}, sh[1:]...), "-c",
				`. "$1"; command -v rdpanel_hbbs_authz_env >/dev/null && echo leaked-function; shift; exec "$@"`, "x", script)
			args = append(append(args, sh...), "-c",
				`printf '%s|%s|%s\n' "${AUTHZ_URL-unset}" "${AUTHZ_SECRET_FILE-unset}" "${_rdp_listen-}"`)
			cmd := exec.Command(sh[0], args...)
			cmd.Env = []string{}
			for k, v := range c.env {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v %v: %v\n%s", sh, c.env, err, out)
			}
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if got, want := lines[len(lines)-1], c.url+"|"+c.key+"|"; got != want {
				t.Errorf("%v %v:\n got %q\nwant %q\n%s", sh, c.env, got, want, out)
			}
			if strings.Contains(string(out), "leaked-function") {
				t.Errorf("%v %v: helper function left defined", sh, c.env)
			}
		}
	}
}

// TestHBBSAuthzKey runs the key-secret helper that creates the hbbs
// authorization secret before hbbs starts.
func TestHBBSAuthzKey(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	script := filepath.Join(rootfs, "usr/libexec/rdpanel/hbbs-authz-key")
	keyRe := regexp.MustCompile(`^[0-9a-f]{64}\n$`)
	path := filepath.Join(t.TempDir(), "panel", "hbbs-authz.key")
	gen := func() string {
		t.Helper()
		out, err := exec.Command(sh, script, path).CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if got := gen(); got != "generated" {
		t.Fatalf("first run: %q", got)
	}
	first, err := os.ReadFile(path)
	if err != nil || !keyRe.Match(first) {
		t.Fatalf("content %q %v", first, err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	if got := gen(); got != "exists" {
		t.Fatalf("second run: %q", got)
	}
	if again, _ := os.ReadFile(path); string(again) != string(first) {
		t.Fatal("existing secret replaced")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
	// The panel reads the very same file.
	if s, src, err := crypto.LoadOrCreateHexSecret(path, hbbsAuthzSecretBytes); err != nil || src != crypto.KeyFromFile ||
		s+"\n" != string(first) {
		t.Fatalf("panel read %q %s %v", s, src, err)
	}
	// An empty file (e.g. a failed earlier write) is replaced.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := gen(); got != "generated" {
		t.Fatalf("empty file: %q", got)
	}
	if b, _ := os.ReadFile(path); !keyRe.Match(b) || string(b) == string(first) {
		t.Fatalf("regenerated content %q", b)
	}
	key, err := os.ReadFile(filepath.Join(rootfs, "usr/libexec/rdpanel/key-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(key), "/usr/libexec/rdpanel/hbbs-authz-key \"$AUTHZ_FILE\"") ||
		!strings.Contains(string(key), "AUTHZ_FILE=${RDPANEL_HBBS_AUTHZ_SECRET_FILE:-$PANEL_DATA/hbbs-authz.key}") {
		t.Fatal("key-secret does not create the hbbs authorization secret")
	}
}

// TestPutFileDoesNotFollowSymlinks covers the helper key-secret writes /data
// with. It runs as root in a directory that belongs to PUID, so a symlink an
// unprivileged process left under the target's name must be replaced, not
// written through, and the mode must land on the new file only.
func TestPutFileDoesNotFollowSymlinks(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	put := func(target, mode, content string) {
		t.Helper()
		cmd := exec.Command(sh, filepath.Join(rootfs, "usr/libexec/rdpanel/put-file"), target, mode)
		cmd.Stdin = strings.NewReader(content)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("put-file %s: %v\n%s", target, err, out)
		}
	}
	check := func(target, mode, content string) {
		t.Helper()
		st, err := os.Lstat(target)
		if err != nil || !st.Mode().IsRegular() {
			t.Fatalf("%s is not a regular file: %v %v", target, st, err)
		}
		if got := st.Mode().Perm().String(); got != mode {
			t.Errorf("%s mode %s, want %s", target, got, mode)
		}
		if b, _ := os.ReadFile(target); string(b) != content {
			t.Errorf("%s content %q", target, b)
		}
	}

	// A plain write, then an existing link (to a file and dangling) under the
	// target's name, and a link under the old fixed temporary name.
	key := filepath.Join(dir, "id_ed25519")
	put(key, "0600", "secret")
	check(key, "-rw-------", "secret")
	for _, link := range []string{"machine-id", "jwt.key"} {
		if err := os.Symlink(victim, filepath.Join(dir, link)); err != nil {
			t.Skipf("no symlinks here: %v", err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "id_ed25519.pub")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "id_ed25519.pub.tmp")); err != nil {
		t.Fatal(err)
	}
	put(filepath.Join(dir, "machine-id"), "0644", "id\n")
	put(filepath.Join(dir, "jwt.key"), "0600", "jwt")
	put(filepath.Join(dir, "id_ed25519.pub"), "0644", "pub")
	check(filepath.Join(dir, "machine-id"), "-rw-r--r--", "id\n")
	check(filepath.Join(dir, "jwt.key"), "-rw-------", "jwt")
	check(filepath.Join(dir, "id_ed25519.pub"), "-rw-r--r--", "pub")
	if _, err := os.Lstat(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Error("put-file created the dangling link's target")
	}
	check(victim, "-rw-------", "untouched")

	// hbbs-authz-key goes through put-file too.
	authz := filepath.Join(dir, "hbbs-authz.key")
	if err := os.Symlink(filepath.Join(dir, "missing"), authz); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sh, filepath.Join(rootfs, "usr/libexec/rdpanel/hbbs-authz-key"), authz).CombinedOutput(); err != nil ||
		strings.TrimSpace(string(out)) != "generated" {
		t.Fatalf("hbbs-authz-key over a dangling link: %v %s", err, out)
	}
	if st, err := os.Lstat(authz); err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		t.Fatalf("hbbs-authz.key: %v %v", st, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Error("hbbs-authz-key wrote through the dangling link")
	}

	// No temporary files are left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("leftover %s", e.Name())
		}
	}

	// key-secret writes through put-file, with no fixed temporary names left.
	ks, err := os.ReadFile(filepath.Join(rootfs, "usr/libexec/rdpanel/key-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ks), ".tmp") || !strings.Contains(string(ks), "PUT=/usr/libexec/rdpanel/put-file") {
		t.Error("key-secret still writes /data without put-file")
	}
	if regexp.MustCompile(`(?m)^\s*chmod [0-7]`).Match(ks) {
		t.Error("key-secret chmods a file directly; use set_mode, which skips symlinks")
	}
}

// TestLogPipelinesFeedTheLogsPage checks the s6 wiring behind Server -> Logs:
// every service has a "<name>-log" consumer running prefix-log <name>, the
// sources prefix-log copies to s6-log are exactly logs.FileSources, and the
// image points rdpanel at the same directory.
func TestLogPipelinesFeedTheLogsPage(t *testing.T) {
	read := func(p string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(rootfs, p))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, svc := range []string{"hbbs", "hbbr", "panel", "agent"} {
		if got := strings.TrimSpace(read("etc/s6-overlay/s6-rc.d/" + svc + "/producer-for")); got != svc+"-log" {
			t.Errorf("%s producer-for = %q", svc, got)
		}
		if run := read("etc/s6-overlay/s6-rc.d/" + svc + "-log/run"); !strings.Contains(run, "prefix-log "+svc) {
			t.Errorf("%s-log/run does not call prefix-log %s:\n%s", svc, svc, run)
		}
	}
	pl := read("usr/libexec/rdpanel/prefix-log")
	if !strings.HasPrefix(pl, "#!/command/with-contenv sh") {
		t.Error("prefix-log needs with-contenv to see RDPANEL_LOGS_*")
	}
	want := `case "$name" in ` + strings.Join(logs.FileSources, " | ") + `) capture=1 ;; esac`
	if !strings.Contains(pl, want) {
		t.Errorf("prefix-log capture list differs from logs.FileSources; want %q", want)
	}
	if !strings.Contains(pl, "RDPANEL_LOGS_DIR-/run/rdpanel/logs") {
		t.Error("prefix-log default dir changed")
	}
	df, err := os.ReadFile("../../deploy/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(df), "RDPANEL_LOGS_DIR=/run/rdpanel/logs") {
		t.Error("Dockerfile must set RDPANEL_LOGS_DIR=/run/rdpanel/logs")
	}
}
