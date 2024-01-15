/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package servers

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/mux"
	"golang.org/x/sync/errgroup"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/remotecommand"
	kremotecommand "k8s.io/kubelet/pkg/cri/streaming/remotecommand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	computev1alpha1 "github.com/ironcore-dev/ironcore/api/compute/v1alpha1"
	"github.com/onmetal/oob-operator/internal/log"
)

// TODO: Integrate oob-console into this codebase

//+kubebuilder:rbac:groups=compute.api.onmetal.de,resources=machines,verbs=get;list;watch
//+kubebuilder:rbac:groups=compute.api.onmetal.de,resources=machinepools,verbs=get;list;watch

func NewConsoleServer(addr string, tlsCert, tlsKey string) (*ConsoleServer, error) {
	return &ConsoleServer{
		addr:    addr,
		tlsCert: tlsCert,
		tlsKey:  tlsKey,
	}, nil
}

// ConsoleServer serves machine consoles over the `kubectl exec` protocol
type ConsoleServer struct {
	addr    string
	tlsCert string
	tlsKey  string
	client.Client
}

func (s *ConsoleServer) Start(ctx context.Context) error {
	ctx = log.WithValues(ctx, "server", "console")
	log.Info(ctx, "Starting server")

	var stop context.CancelFunc
	ctx, stop = context.WithCancel(ctx)
	defer stop()

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}

	h := mux.NewRouter()
	r := h.PathPrefix("/apis/compute.api.onmetal.de").Subrouter().Methods(http.MethodGet, http.MethodPost).Path("/namespaces/{namespace}/machines/{machine}/exec")
	r.HandlerFunc(s.serve)

	srv := &http.Server{
		Handler: h,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	var g *errgroup.Group
	g, ctx = errgroup.WithContext(ctx)

	g.Go(func() error {
		defer stop()

		log.Info(ctx, "Listening", "bindAddr", s.addr)
		err1 := srv.ServeTLS(ln, s.tlsCert, s.tlsKey)
		if err1 != nil && !errors.Is(err1, http.ErrServerClosed) {
			return err
		}

		return nil
	})

	g.Go(func() error {
		<-ctx.Done()
		log.Info(ctx, "Stopping server")
		sdCtx, sdCancel := context.WithTimeout(context.Background(), time.Second*3)
		defer sdCancel()
		err2 := srv.Shutdown(sdCtx)
		if err2 != nil {
			return fmt.Errorf("could not shutdown HTTPS server cleanly: %w", err)
		}
		log.Info(ctx, "Server finished")

		return nil
	})

	return g.Wait()
}

func (s *ConsoleServer) serve(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	c := &console{}
	opts := &kremotecommand.Options{
		Stdin:  true,
		Stdout: true,
		TTY:    true,
	}
	supportedStreamProtocols := strings.Split(req.Header.Get("X-Stream-Protocol-Version"), ",")
	defer func() {
		kremotecommand.ServeExec(w, req.WithContext(ctx), c, "", "", "", []string{}, opts, time.Minute*60, time.Minute, supportedStreamProtocols)
	}()

	id := make([]byte, 4)
	n, err := rand.Read(id)
	if err != nil || n != 4 {
		c.err = fmt.Errorf("cannot generate request id: %w", err)
		return
	}
	ctx = log.WithValues(ctx, "requestID", fmt.Sprintf("%x", id))

	vars := mux.Vars(req)
	namespace := vars["namespace"]
	machineName := vars["machine"]
	if machineName == "" {
		c.err = fmt.Errorf("machine name not specified")
		return
	}
	ctx = log.WithValues(ctx, "namespace", namespace, "machine", machineName)

	var machine computev1alpha1.Machine
	err = s.Get(ctx, client.ObjectKey{Namespace: namespace, Name: machineName}, &machine)
	if err != nil {
		c.err = fmt.Errorf("cannot get machine: %w", err)
		return
	}
	if machine.Spec.MachinePoolRef == nil || machine.Spec.MachinePoolRef.Name == "" {
		c.err = fmt.Errorf("machine has no machine pool reference")
		return
	}

	var pool computev1alpha1.MachinePool
	err = s.Get(ctx, client.ObjectKey{Name: machine.Spec.MachinePoolRef.Name}, &pool)
	if err != nil {
		c.err = fmt.Errorf("cannot get machine pool: %w", err)
		return
	}

	c.name = pool.Annotations["metal-api.onmetal.de/oob-name"]
	if c.name == "" {
		c.err = fmt.Errorf("machine pool does not have metal-api.onmetal.de/oob-name annotation")
		return
	}

	c.namespace = pool.Annotations["metal-api.onmetal.de/oob-namespace"]
	if c.namespace == "" {
		c.err = fmt.Errorf("machine pool does not have metal-api.onmetal.de/oob-namespace annotation")
		return
	}

	ctx = log.WithValues(ctx, "oob", c.name, "oobNamespace", c.namespace)
}

type console struct {
	name      string
	namespace string
	err       error
}

func (c *console) ExecInContainer(ctx context.Context, _ string, _ types.UID, _ string, _ []string, in io.Reader, out, _ io.WriteCloser, tty bool, resize <-chan remotecommand.TerminalSize, _ time.Duration) error {
	if c.err != nil {
		return logError(ctx, c.err)
	}
	return c.exec(ctx, in, out, tty, resize)
}

func (c *console) exec(ctx context.Context, in io.Reader, out io.WriteCloser, tty bool, resize <-chan remotecommand.TerminalSize) error {
	if !tty {
		return logError(ctx, fmt.Errorf("console access requires a TTY"))
	}

	var stop context.CancelFunc
	ctx, stop = context.WithCancel(ctx)
	defer stop()

	cmd := exec.CommandContext(ctx, "./oob-console", "--silent", fmt.Sprintf("-n=%s", c.namespace), c.name)
	cmd.WaitDelay = time.Second * 7
	cmd.Cancel = func() error {
		log.Debug(ctx, "Sending SIGTERM to console process")
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	log.Info(ctx, "Running console")
	ptyf, err := pty.Start(cmd)
	if err != nil {
		return logError(ctx, fmt.Errorf("cannot run command: %w", err))
	}
	defer func() { _ = ptyf.Close() }()

	var closeOnce sync.Once
	closeF := func() {
		log.Debug(ctx, "Sending SIGHUP to console process")
		_ = cmd.Process.Signal(syscall.SIGHUP)
		_ = out.Close()
		_ = ptyf.Close()
	}
	go func() {
		_, _ = io.Copy(ptyf, in)
		closeOnce.Do(closeF)
	}()
	go func() {
		_, _ = io.Copy(out, ptyf)
		closeOnce.Do(closeF)
	}()
	go func() {
		for {
			select {
			case ts := <-resize:
				szErr := pty.Setsize(ptyf, &pty.Winsize{
					Rows: ts.Height,
					Cols: ts.Width,
				})
				if szErr != nil {
					log.Error(ctx, fmt.Errorf("cannot resize console PTY: %w", szErr))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	_ = cmd.Wait()
	log.Info(ctx, "Console finished")

	return nil
}

func logError(ctx context.Context, err error) error {
	log.Error(ctx, err)
	return err
}

// SetupWithManager sets up the server with the Manager.
func (s *ConsoleServer) SetupWithManager(mgr ctrl.Manager) error {
	s.Client = mgr.GetClient()

	return mgr.Add(s)
}
