package stdiotransport

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The tests use the test binary itself as the stdio child, re-entered through
// TestMain when these variables are set.
const (
	fakeChildEnv        = "TAILGATE_STDIO_FAKE_CHILD"
	fakeChildLinger     = "TAILGATE_STDIO_FAKE_CHILD_LINGER"
	fakeChildGrandchild = "TAILGATE_STDIO_FAKE_CHILD_GRANDCHILD"
	fakeChildExitOnly   = "TAILGATE_STDIO_FAKE_CHILD_EXIT_ON_START"
	fakeChildSilent     = "TAILGATE_STDIO_FAKE_CHILD_SILENT"
	// fakeChildStderrFlood makes the child open with one diagnostic line longer
	// than the reader can frame, and go on writing after it.
	fakeChildStderrFlood = "TAILGATE_STDIO_FAKE_CHILD_STDERR_FLOOD"
	// fakeChildDiscover chooses how the child answers server/discover.
	// "answer" stands in for a server written against the stateless revision.
	// Any other value is a JSON-RPC error code to refuse with, which is how the
	// servers written before it refuse a method they have never heard of: the
	// SDKs disagree on which code that is. Unset means -32601.
	fakeChildDiscover = "TAILGATE_STDIO_FAKE_CHILD_DISCOVER"
	// fakeChildDiscoverAnswers is the value that makes the child implement it.
	fakeChildDiscoverAnswers = "answer"
)

// Codes real MCP servers have been observed refusing an unknown pre-initialize
// method with. Only the first is the one the older revision was assumed to use.
const (
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeUndefined      = 0
)

// Methods the fake child answers specially. Every other method echoes back.
const (
	slowMethod   = "test/slow"
	silentMethod = "test/silent"
	exitMethod   = "test/exit"
	floodMethod  = "test/flood"
	deafMethod   = "test/deaf"
	envMethod    = "test/env"
)

// runFakeChild is a minimal stdio MCP server: one JSON-RPC message per line,
// each handled on its own goroutine so responses come back out of request
// order and correlation cannot pass by luck of sequencing.
func runFakeChild() {
	if os.Getenv(fakeChildExitOnly) != "" {
		os.Exit(1)
	}
	floodStderr()
	silent := os.Getenv(fakeChildSilent) != ""
	grandchildPid := startGrandchild()

	var writes sync.Mutex
	var handlers sync.WaitGroup
	out := bufio.NewWriter(os.Stdout)
	respond := func(line string) {
		writes.Lock()
		defer writes.Unlock()
		fmt.Fprintln(out, line)
		out.Flush()
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for scanner.Scan() {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				DelayMS int    `json:"delay_ms"`
				Echo    string `json:"echo"`
				// Notify asks the child to emit this many notifications after
				// answering, which is what a subscription stream carries.
				Notify int `json:"notify"`
				// End asks the child to answer a subscriptions/listen request,
				// which is how the revision ends a subscription.
				End bool `json:"end"`
			} `json:"params"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			continue
		}
		if len(request.ID) == 0 {
			continue
		}
		if request.Method == deafMethod {
			// Answering and then never reading stdin again, while staying
			// alive, is what fills the parent's pipe buffer.
			respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"deaf":true}}`, request.ID))
			time.Sleep(time.Hour)
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			if request.Params.DelayMS > 0 {
				time.Sleep(time.Duration(request.Params.DelayMS) * time.Millisecond)
			}
			switch {
			case silent, request.Method == silentMethod:
			case request.Method == exitMethod:
				os.Exit(3)
			case request.Method == listenMethod:
				// A conforming child acknowledges with a notification, streams
				// for as long as the subscription lasts, and answers the
				// request itself only to end it. The end param is what asks it
				// to. Without it the subscription simply stays open.
				respond(`{"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{}}`)
				for i := range request.Params.Notify {
					respond(fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/message","params":{"seq":%d,"echo":%q}}`, i, request.Params.Echo))
				}
				if request.Params.End {
					respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"ended":true}}`, request.ID))
				}
				return
			case request.Method == initializeMethod:
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"grandchildPid":%d,"serverInfo":{"name":"fake-stdio-server","version":"0.0.1"}}}`, request.ID, grandchildPid))
			case request.Method == discoverMethod && os.Getenv(fakeChildDiscover) == fakeChildDiscoverAnswers:
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersions":["2026-07-28"],"serverInfo":{"name":"fake-stdio-server","version":"0.0.1"}}}`, request.ID))
			case request.Method == discoverMethod:
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":"Refused"}}`, request.ID, discoverRefusalCode()))
			case request.Method == envMethod:
				// The echo param names the variable to report.
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"value":%q}}`, request.ID, os.Getenv(request.Params.Echo)))
			case request.Method == floodMethod:
				// One line past what the reader will frame, standing in for a
				// tools/call result too large to parse.
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"blob":%q}}`, request.ID, strings.Repeat("x", maxLineBytes)))
			default:
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"method":%q,"echo":%q}}`, request.ID, request.Method, request.Params.Echo))
			}
			for i := range request.Params.Notify {
				respond(fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/message","params":{"seq":%d,"echo":%q}}`, i, request.Params.Echo))
			}
		}()
	}
	handlers.Wait()
	lingerAfterStdinClose()
}

// discoverRefusalCode is the code the child refuses server/discover with.
func discoverRefusalCode() int {
	code, err := strconv.Atoi(os.Getenv(fakeChildDiscover))
	if err != nil {
		return codeMethodNotFound
	}
	return code
}

// floodStderr writes one line past what the parent can frame, before the child
// has read anything. A parent that stops draining stderr there leaves the rest
// of the write with nowhere to go, and the child never reaches its stdin loop.
func floodStderr() {
	if os.Getenv(fakeChildStderrFlood) == "" {
		return
	}
	os.Stderr.Write(bytes.Repeat([]byte("x"), maxLineBytes+(1<<20)))
}

// startGrandchild stands in for the wrapper case, where the configured command
// is a launcher and the real MCP server is its child.
func startGrandchild() int {
	if os.Getenv(fakeChildGrandchild) == "" {
		return 0
	}
	grandchild := exec.Command("sleep", "300")
	if err := grandchild.Start(); err != nil {
		return 0
	}
	return grandchild.Process.Pid
}

func lingerAfterStdinClose() {
	if os.Getenv(fakeChildLinger) != "" {
		// Ignoring the stdin close forces the kill path. Sleeping rather than
		// blocking forever keeps the runtime's deadlock detector from ending
		// the process on its own, which would fake the very exit under test.
		time.Sleep(time.Hour)
	}
	os.Exit(0)
}
