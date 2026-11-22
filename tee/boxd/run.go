package main

// Target "run" (AB#364): the customer job over the sealed stream. The client uploads a static
// binary, the box runs it once and returns its exit code and output, all inside the stream.
//
//	C -> B  {"size":N,"args":[...],"timeout_s":T}       one frame
//	C -> B  N bytes of the binary                        in frames of at most maxData
//	B -> C  {"exit":E,"bytes":L,"truncated":b,"timed_out":b,"signal":"","sha256":"..."}
//	B -> C  L bytes of combined stdout and stderr        in frames of at most maxData
//
// On any refusal the box sends {"error":"..."} and closes. exit is -1 when the process did not
// exit on its own (killed by a signal or by the timeout); signal then names the signal.
//
// The uploaded code must not reach what makes the box trustworthy: boxd runs as root, and root
// could ask configfs-tsm for a report over its own REPORT_DATA or read boxd's keys out of /proc.
// So when boxd is root the child runs as an unprivileged uid in its own process group and its own
// pid, mount and network namespaces, with a private filesystem root containing only the static
// job. Namespace cloning alone does not hide pathname sockets such as the desktop X11 socket.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	runMaxSize        = 64 << 20
	runMaxArgs        = 64
	runMaxArgLen      = 4096
	runMaxOutput      = 1 << 20
	runDefaultTimeout = 30
	runMaxTimeout     = 300
	runUploadWindow   = 120 * time.Second
	runUID            = 65534 // nobody
)

// One job at a time: each holds the binary in memory and on tmpfs, and the box is 4 GiB.
var runMu sync.Mutex

type runRequest struct {
	Size     int      `json:"size"`
	Args     []string `json:"args"`
	TimeoutS int      `json:"timeout_s"`
}

type runResult struct {
	Exit      int    `json:"exit"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
	TimedOut  bool   `json:"timed_out"`
	Signal    string `json:"signal,omitempty"`
	SHA256    string `json:"sha256"`
}

func serveRun(c net.Conn, send, recv *cipherState) {
	reply := func(b []byte) bool {
		ct, err := send.encrypt(b)
		return err == nil && writeFrame(c, ct) == nil
	}
	refuse := func(msg string) {
		b, _ := json.Marshal(map[string]string{"error": msg})
		reply(b)
	}
	if !runMu.TryLock() {
		refuse("busy")
		return
	}
	defer runMu.Unlock()

	// The handshake cleared the deadline; a stalled upload must not pin memory forever.
	c.SetReadDeadline(time.Now().Add(runUploadWindow))
	readPlain := func() ([]byte, error) {
		ct, err := readFrame(c)
		if err != nil {
			return nil, err
		}
		return recv.decrypt(ct)
	}
	hdr, err := readPlain()
	if err != nil {
		return
	}
	var req runRequest
	if err := json.Unmarshal(hdr, &req); err != nil {
		refuse("bad header")
		return
	}
	if msg := checkRunRequest(&req); msg != "" {
		refuse(msg)
		return
	}
	bin := make([]byte, 0, req.Size)
	for len(bin) < req.Size {
		pt, err := readPlain()
		if err != nil {
			return
		}
		if len(bin)+len(pt) > req.Size {
			refuse("more bytes than size")
			return
		}
		bin = append(bin, pt...)
	}
	c.SetReadDeadline(time.Time{})
	console("RUN " + hex.EncodeToString(sha256Of(bin))[:16])

	// The client sends nothing while the job runs, so a read that returns means it hung up (or broke the
	// protocol): stop the job then, instead of holding runMu and the box for the rest of the timeout.
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		var one [1]byte
		c.Read(one[:])
		cancelRun()
	}()
	res, out, err := runBinary(runCtx, bin, req.Args, time.Duration(req.TimeoutS)*time.Second)
	// Wake the watcher and wait for it, so no reader is left on the connection while we reply.
	c.SetReadDeadline(time.Now())
	<-watched
	c.SetReadDeadline(time.Time{})
	if err != nil {
		refuse(err.Error())
		return
	}
	rj, _ := json.Marshal(res)
	if !reply(rj) {
		return
	}
	for o := 0; o < len(out); o += maxData {
		end := min(o+maxData, len(out))
		if !reply(out[o:end]) {
			return
		}
	}
}

func checkRunRequest(req *runRequest) string {
	if req.Size <= 0 || req.Size > runMaxSize {
		return "size out of range"
	}
	if len(req.Args) > runMaxArgs {
		return "too many args"
	}
	for _, a := range req.Args {
		if len(a) > runMaxArgLen {
			return "arg too long"
		}
	}
	if req.TimeoutS == 0 {
		req.TimeoutS = runDefaultTimeout
	}
	if req.TimeoutS < 1 || req.TimeoutS > runMaxTimeout {
		return "timeout out of range"
	}
	return ""
}

func sha256Of(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// cappedBuffer keeps the first max bytes and drains the rest, so a chatty child never blocks on
// a full pipe.
type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room < len(p) {
		b.truncated = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

func runBinary(parent context.Context, bin []byte, args []string, timeout time.Duration) (runResult, []byte, error) {
	res := runResult{SHA256: hex.EncodeToString(sha256Of(bin))}
	if os.Geteuid() != 0 {
		return res, nil, errors.New("isolated execution requires root")
	}
	dir, err := os.MkdirTemp("", "run-")
	if err != nil {
		return res, nil, errors.New("no scratch space")
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o711); err != nil {
		return res, nil, errors.New("no scratch space")
	}
	if err := storeRunBinary(dir, bin); err != nil {
		return res, nil, err
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := isolatedRunCommand(ctx, dir, args)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/"}
	out := &cappedBuffer{max: runMaxOutput}
	cmd.Stdout, cmd.Stderr = out, out
	// Kill the whole process group, not just the direct child, and stop waiting on pipes that a
	// forked descendant still holds.
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second

	err = cmd.Run()
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	res.TimedOut = ctx.Err() == context.DeadlineExceeded
	var ee *exec.ExitError
	switch {
	case err == nil:
		res.Exit = 0
	case errors.As(err, &ee):
		res.Exit = ee.ExitCode()
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res.Signal = ws.Signal().String()
		}
	case res.TimedOut || errors.Is(err, exec.ErrWaitDelay):
		res.Exit = -1
	default:
		return res, nil, errors.New("could not start binary: " + err.Error())
	}
	res.Bytes, res.Truncated = out.buf.Len(), out.truncated
	return res, out.buf.Bytes(), nil
}

// The executable is static: it needs no host libraries, devices, procfs or desktop IPC.
// Chroot occurs before dropping privileges in os/exec; the root is not writable by the job.
func isolatedRunCommand(ctx context.Context, root string, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/job", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:    true,
		Chroot:     root,
		Credential: &syscall.Credential{Uid: runUID, Gid: runUID, NoSetGroups: true},
		Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET,
	}
	return cmd
}

func storeRunBinary(dir string, bin []byte) error {
	path := filepath.Join(dir, "job")
	if err := os.WriteFile(path, bin, 0o755); err != nil {
		return errors.New("could not store binary")
	}
	// WriteFile applies the daemon umask; the dropped uid still needs execute permission.
	if err := os.Chmod(path, 0o555); err != nil {
		return errors.New("could not prepare binary")
	}
	return nil
}
