package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"syscall"

	restserver "github.com/restic/rest-server"
	"github.com/spf13/cobra"
)

type restServerApp struct {
	CmdRoot    *cobra.Command
	Server     restserver.Server
	CpuProfile string

	listenerAddressMu sync.Mutex
	listenerAddress   net.Addr // set after startup
}

// cmdRoot is the base command when no other command has been specified.
func newRestServerApp() *restServerApp {
	rv := &restServerApp{
		CmdRoot: &cobra.Command{
			Use:           "rest-server",
			Short:         "Run a REST server for use with restic",
			SilenceErrors: true,
			SilenceUsage:  true,
			Args: func(cmd *cobra.Command, args []string) error {
				if len(args) != 0 {
					return fmt.Errorf("rest-server expects no arguments - unknown argument: %s", args[0])
				}
				return nil
			},
			Version: fmt.Sprintf("rest-server %s compiled with %v on %v/%v\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH),
		},
		Server: restserver.Server{
			Path:   filepath.Join(os.TempDir(), "restic"),
			Listen: ":8000",
		},
	}
	rv.CmdRoot.RunE = rv.runRoot
	flags := rv.CmdRoot.Flags()

	flags.StringVar(&rv.CpuProfile, "cpu-profile", rv.CpuProfile, "write CPU profile to file")
	flags.BoolVar(&rv.Server.Debug, "debug", rv.Server.Debug, "output debug messages")
	flags.StringVar(&rv.Server.Listen, "listen", rv.Server.Listen, "listen address")
	flags.StringVar(&rv.Server.Log, "log", rv.Server.Log, "write HTTP requests in the combined log format to the specified `filename` (use \"-\" for logging to stdout)")
	flags.Int64Var(&rv.Server.MaxRepoSize, "max-size", rv.Server.MaxRepoSize, "the maximum size of the repository in bytes")
	flags.StringVar(&rv.Server.Path, "path", rv.Server.Path, "data directory")
	flags.BoolVar(&rv.Server.TLS, "tls", rv.Server.TLS, "turn on TLS support")
	flags.StringVar(&rv.Server.TLSCert, "tls-cert", rv.Server.TLSCert, "TLS certificate path")
	flags.StringVar(&rv.Server.TLSKey, "tls-key", rv.Server.TLSKey, "TLS key path")
	flags.BoolVar(&rv.Server.NoAuth, "no-auth", rv.Server.NoAuth, "disable .htpasswd authentication")
	flags.StringVar(&rv.Server.HtpasswdPath, "htpasswd-file", rv.Server.HtpasswdPath, "location of .htpasswd file (default: \"<data directory>/.htpasswd)\"")
	flags.BoolVar(&rv.Server.NoVerifyUpload, "no-verify-upload", rv.Server.NoVerifyUpload,
		"do not verify the integrity of uploaded data. DO NOT enable unless the rest-server runs on a very low-power device")
	flags.BoolVar(&rv.Server.AppendOnly, "append-only", rv.Server.AppendOnly, "enable append only mode")
	flags.BoolVar(&rv.Server.PrivateRepos, "private-repos", rv.Server.PrivateRepos, "users can only access their private repo")
	flags.BoolVar(&rv.Server.Prometheus, "prometheus", rv.Server.Prometheus, "enable Prometheus metrics")
	flags.BoolVar(&rv.Server.PrometheusNoAuth, "prometheus-no-auth", rv.Server.PrometheusNoAuth, "disable auth for Prometheus /metrics endpoint")

	return rv
}

var version = "0.13.0"

func (app *restServerApp) tlsSettings() (bool, string, string, error) {
	var key, cert string
	if !app.Server.TLS && (app.Server.TLSKey != "" || app.Server.TLSCert != "") {
		return false, "", "", errors.New("requires enabled TLS")
	} else if !app.Server.TLS {
		return false, "", "", nil
	}
	if app.Server.TLSKey != "" {
		key = app.Server.TLSKey
	} else {
		key = filepath.Join(app.Server.Path, "private_key")
	}
	if app.Server.TLSCert != "" {
		cert = app.Server.TLSCert
	} else {
		cert = filepath.Join(app.Server.Path, "public_key")
	}
	return app.Server.TLS, key, cert, nil
}

// returns the address that the app is listening on.
// returns nil if the application hasn't finished starting yet
func (app *restServerApp) ListenerAddress() net.Addr {
	app.listenerAddressMu.Lock()
	defer app.listenerAddressMu.Unlock()
	return app.listenerAddress
}

// See the "Notes" section of the Go net package documentation for more
// details.
func osRequiresSeparateTcp6Listener() bool {
	switch runtime.GOOS {
	case "openbsd":
		return true
	case "dragonfly":
		return true
	default:
		return false
	}
}

func (app *restServerApp) runRoot(cmd *cobra.Command, args []string) error {
	log.SetFlags(0)

	log.Printf("Data directory: %s", app.Server.Path)

	if app.CpuProfile != "" {
		f, err := os.Create(app.CpuProfile)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()

		log.Println("CPU profiling enabled")
		defer log.Println("Stopped CPU profiling")
	}

	if app.Server.NoAuth {
		log.Println("Authentication disabled")
	} else {
		log.Println("Authentication enabled")
	}

	handler, err := restserver.NewHandler(&app.Server)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	if app.Server.AppendOnly {
		log.Println("Append only mode enabled")
	} else {
		log.Println("Append only mode disabled")
	}

	if app.Server.PrivateRepos {
		log.Println("Private repositories enabled")
	} else {
		log.Println("Private repositories disabled")
	}

	enabledTLS, privateKey, publicKey, err := app.tlsSettings()
	if err != nil {
		return err
	}

	listener_tcp, err_tcp := findListener(app.Server.Listen, "tcp")
	if !osRequiresSeparateTcp6Listener() && err_tcp != nil {
		return fmt.Errorf("unable to listen: %w", err_tcp)
	}

	var listener_tcp6 net.Listener = nil
	var err_tcp6 error = nil
	if osRequiresSeparateTcp6Listener() {
		listener_tcp6, err_tcp6 = findListener(app.Server.Listen, "tcp6")

		if err_tcp != nil && err_tcp6 != nil {
			return fmt.Errorf("unable to listen: tcp error: %w, tcp6 error: %w", err_tcp, err_tcp6)
		} else if err_tcp != nil {
			log.Printf("warning: %s", err_tcp)
		} else if err_tcp6 != nil {
			log.Printf("warning: %s", err_tcp6)
		}
	} else {
		// set listener address, this is useful for tests
		app.listenerAddressMu.Lock()
		app.listenerAddress = listener_tcp.Addr()
		app.listenerAddressMu.Unlock()
	}

	runServer := func(listener net.Listener, srv *http.Server, serverType string) {
		var err error = nil

		if !enabledTLS {
			err = srv.Serve(listener)
		} else {
			log.Printf("%s: TLS enabled, private key %s, pubkey %v", serverType, privateKey, publicKey)
			err = srv.ServeTLS(listener, publicKey, privateKey)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("%s: listen and serve returned err: %v", serverType, err)
		}
	}

	var srv_tcp *http.Server = nil
	var srv_tcp6 *http.Server = nil

	// run server(s) in background
	if listener_tcp != nil {
		srv_tcp = &http.Server{
			Handler: handler,
		}
		go runServer(listener_tcp, srv_tcp, "tcp")
	}
	if listener_tcp6 != nil {
		srv_tcp6 = &http.Server{
			Handler: handler,
		}
		go runServer(listener_tcp6, srv_tcp6, "tcp6")
	}

	// wait until done
	<-app.CmdRoot.Context().Done()

	// gracefully shutdown server(s)
	err_tcp = nil
	err_tcp6 = nil
	if srv_tcp != nil {
		err_tcp = srv_tcp.Shutdown(context.Background());
	}
	if srv_tcp6 != nil {
		err_tcp6 = srv_tcp6.Shutdown(context.Background());
	}

	if err_tcp != nil && err_tcp6 != nil {
		return fmt.Errorf("server shutdown returned an err: tcp: %w, tcp6: %w", err_tcp, err_tcp6)
	} else if err_tcp != nil {
		return fmt.Errorf("server shutdown returned an err: tcp: %w", err_tcp)
	} else if err_tcp6 != nil {
		return fmt.Errorf("server shutdown returned an err: tcp6: %w", err_tcp6)
	}

	log.Println("shutdown cleanly")
	return nil
}

func main() {
	// create context to be notified on interrupt or term signal so that we can shutdown cleanly
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := newRestServerApp().CmdRoot.ExecuteContext(ctx); err != nil {
		log.Fatalf("error: %v", err)
	}
}
