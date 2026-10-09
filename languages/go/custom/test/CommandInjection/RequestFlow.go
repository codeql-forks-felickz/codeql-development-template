package main

// Request data reaching `exec.Command` directly or through a wrapper. These are already
// reported by the upstream `go/command-injection` query and are kept as regression tests.

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
)

// system runs `cmd` with a shell.
func system(ctx context.Context, cmd string) ([]byte, error) {
	return exec.CommandContext(ctx, "sh", "-c", cmd).CombinedOutput() // BAD (via healthHandler)
}

// A request parameter appended to a ping command line that a wrapper runs with `sh -c`.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	extra := r.FormValue("extra")
	output, _ := system(r.Context(), "ping -c1 example.com"+extra)
	w.Write(output)
}

func directHandler(w http.ResponseWriter, r *http.Request) {
	extra := r.URL.Query().Get("extra")
	exec.Command("sh", "-c", "ping -c 1 "+extra).Run() // BAD

	parts := strings.Fields(r.FormValue("cmd"))
	exec.Command(parts[0], parts[1:]...).Run() // BAD

	exec.Command("ping", "-c", "1", "example.com").Run() // GOOD: constant command
}
