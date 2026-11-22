package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestStoredRunIgnoresRestrictiveUmask(t *testing.T) {
	dir := t.TempDir()
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	if err := storeRunBinary(dir, []byte("static job")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, "job"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o555 {
		t.Fatalf("job mode %o", st.Mode().Perm())
	}
}

func TestRunCommandConfinesFilesystem(t *testing.T) {
	cmd := isolatedRunCommand(context.Background(), "/private/job-root", nil)
	a := cmd.SysProcAttr
	if cmd.Path != "/job" || a.Chroot != "/private/job-root" || !a.Setpgid || a.Credential.Uid != runUID || a.Credential.Gid != runUID || !a.Credential.NoSetGroups {
		t.Fatal("missing execution boundary")
	}
	if a.Cloneflags != syscall.CLONE_NEWNS|syscall.CLONE_NEWPID|syscall.CLONE_NEWNET {
		t.Fatal("missing namespaces")
	}
}

func TestRunRootHidesHostFilesAndSockets(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chroot requires root")
	}
	outer, err := os.MkdirTemp("", "boxd-isolation-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outer)
	if err := os.Chmod(outer, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outer, "host-secret")
	if err := os.WriteFile(sentinel, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(outer, "desktop.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0o777); err != nil {
		t.Fatal(err)
	}
	source := `package main
import("fmt";"net";"os")
func main(){
 if os.Getuid()!=65534 {panic("not nobody")}
 if _,e:=os.ReadFile(os.Args[1]);e==nil {panic("host file visible")}
 if c,e:=net.Dial("unix",os.Args[2]);e==nil {c.Close();panic("host socket reachable")}
 if _,e:=os.Stat("/proc");e==nil {panic("host proc visible")}
 if e:=os.WriteFile("/new",[]byte("x"),0600);e==nil {panic("root writable")}
 if _,e:=os.Stat("/job");e!=nil {panic(e)}
 fmt.Print("isolated")
}`
	src := filepath.Join(outer, "probe.go")
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	built := filepath.Join(outer, "probe")
	build := exec.Command("go", "build", "-o", built, src)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("static probe: %v %s", err, out)
	}
	bin, err := os.ReadFile(built)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("", "boxd-job-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := storeRunBinary(root, bin); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := isolatedRunCommand(ctx, root, []string{sentinel, socket})
	cmd.Dir = "/"
	// Exercise real chroot + uid drop even where the test host disallows namespace cloning.
	// Production namespace flags are independently asserted above and never relaxed there.
	cmd.SysProcAttr.Cloneflags = 0
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("confined execution: %v %s", err, out)
	}
	if strings.TrimSpace(string(out)) != "isolated" {
		t.Fatalf("unexpected result %q", out)
	}
}
