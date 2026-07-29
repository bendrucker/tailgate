package tsnetserver

import (
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"runtime"
	"sync"
)

// loginURLPattern matches the interactive login URL tsnet reports when a node
// joins without an auth key. tsnet has no accessor for it: the URL reaches a
// caller only through UserLogf, so it is recovered from the message text.
var loginURLPattern = regexp.MustCompile(`https://login\.tailscale\.com/[^\s"']+`)

// opener hands a login URL to the platform's default URL handler. tsnet
// reprints the URL every few seconds until the node joins, so the opener fires
// on the first one and ignores the rest rather than reopening a browser tab on
// a timer.
type opener struct {
	open   func(url string) error
	logger *slog.Logger
	once   sync.Once
}

// userLogf wraps a tsnet UserLogf so the message still reaches the logger and a
// login URL in it also reaches the browser.
func (o *opener) userLogf(next func(format string, args ...any)) func(format string, args ...any) {
	return func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		next("%s", message)

		if url := loginURLPattern.FindString(message); url != "" {
			o.once.Do(func() { o.launch(url) })
		}
	}
}

func (o *opener) launch(url string) {
	if err := o.open(url); err != nil {
		// The URL is already logged, so a failed open costs the caller a copy
		// and paste rather than the ability to join.
		o.logger.Warn("could not open the login URL", "url", url, "err", err)
		return
	}
	o.logger.Info("opened the login URL", "url", url)
}

// openURL launches url with the platform's default handler.
func openURL(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
