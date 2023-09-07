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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/remotecommand"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	computev1alpha1 "github.com/onmetal/onmetal-api/api/compute/v1alpha1"
	"github.com/onmetal/oob-operator/log"
	virtlethttp "github.com/onmetal/virtlet/machinepoolletutils/terminal/http"
)

// TODO: Remove dependency on virtlet
// TODO: Integrate oob-console into this codebase

//+kubebuilder:rbac:groups=compute.api.onmetal.de,resources=machines,verbs=get;list;watch
//+kubebuilder:rbac:groups=compute.api.onmetal.de,resources=machinepools,verbs=get;list;watch

// ConsoleServer serves machine consoles over the `kubectl exec` protocol
type ConsoleServer struct {
	client.Client
	Address string
	TLSCert string
	TLSKey  string
}

func (s *ConsoleServer) Start(ctx context.Context) error {
	ctx = log.WithValues(ctx, "server", "console")
	log.Info(ctx, "Starting server")

	var stop context.CancelFunc
	ctx, stop = context.WithCancel(ctx)
	defer stop()

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.Address)
	if err != nil {
		return err
	}

	h := mux.NewRouter()
	r := h.PathPrefix("/apis/compute.api.onmetal.de").Subrouter().Methods(http.MethodGet, http.MethodPost).Path("/namespaces/{namespace}/machines/{machine}/exec")
	r.HandlerFunc(s.serve)

	srv := &http.Server{
		Handler: h,
		BaseContext: func(listener net.Listener) context.Context {
			return ctx
		},
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stop()

		log.Info(ctx, "Listening", "bindAddr", s.Address)
		err1 := srv.ServeTLS(ln, s.TLSCert, s.TLSKey)
		if err1 != nil && !errors.Is(err1, http.ErrServerClosed) {
			log.Error(ctx, fmt.Errorf("error while running HTTPS server: %w", err))
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		<-ctx.Done()
		log.Info(ctx, "Stopping server")
		sdCtx, sdCancel := context.WithTimeout(context.Background(), time.Second*3)
		defer sdCancel()
		err2 := srv.Shutdown(sdCtx)
		if err2 != nil {
			log.Error(ctx, fmt.Errorf("could not shutdown HTTPS server cleanly: %w", err))
		}
		log.Info(ctx, "Server finished")
	}()

	return nil
}

func (s *ConsoleServer) serve(w http.ResponseWriter, req *http.Request) {
	opts := &virtlethttp.Options{
		Stdin:  true,
		Stdout: true,
		TTY:    true,
	}
	supportedStreamProtocols := strings.Split(req.Header.Get("X-Stream-Protocol-Version"), ",")
	c := &console{
		ctx: req.Context(),
	}
	defer virtlethttp.Serve(w, req, c, opts, time.Minute*60, time.Minute, supportedStreamProtocols)

	id := make([]byte, 4)
	n, err := rand.Read(id)
	if err != nil || n != 4 {
		c.err = fmt.Errorf("cannot generate request id: %w", err)
		return
	}
	c.ctx = log.WithValues(req.Context(), "requestID", fmt.Sprintf("%x", id))

	vars := mux.Vars(req)
	namespace := vars["namespace"]
	machineName := vars["machine"]
	if machineName == "" {
		c.err = fmt.Errorf("machine name not specified")
		return
	}
	c.ctx = log.WithValues(c.ctx, "namespace", namespace, "machine", machineName)

	var machine computev1alpha1.Machine
	err = s.Get(c.ctx, types.NamespacedName{Namespace: namespace, Name: machineName}, &machine)
	if err != nil {
		c.err = fmt.Errorf("cannot get machine: %w", err)
		return
	}
	if machine.Spec.MachinePoolRef == nil || machine.Spec.MachinePoolRef.Name == "" {
		c.err = fmt.Errorf("machine has no machine pool reference")
		return
	}

	var pool computev1alpha1.MachinePool
	err = s.Get(c.ctx, types.NamespacedName{Name: machine.Spec.MachinePoolRef.Name}, &pool)
	if err != nil {
		c.err = fmt.Errorf("cannot get machine pool: %w", err)
		return
	}

	c.oob = pool.Annotations["metal-api.onmetal.de/oob-name"]
	if c.oob == "" {
		c.err = fmt.Errorf("machine pool does not have metal-api.onmetal.de/oob-name annotation")
		return
	}

	c.namespace = pool.Annotations["metal-api.onmetal.de/oob-namespace"]
	if c.namespace == "" {
		c.err = fmt.Errorf("machine pool does not have metal-api.onmetal.de/oob-namespace annotation")
		return
	}

	c.ctx = log.WithValues(c.ctx, "oob", c.oob, "oobNamespace", c.namespace)
}

type console struct {
	ctx       context.Context
	namespace string
	oob       string
	err       error
}

func (c *console) Run(in io.Reader, out, _ io.WriteCloser, resize <-chan remotecommand.TerminalSize) error {
	if c.err != nil {
		return c.err
	}

	var stop context.CancelFunc
	c.ctx, stop = context.WithCancel(c.ctx)
	defer stop()

	cmd := exec.CommandContext(c.ctx, "./oob-console", "--silent", fmt.Sprintf("-n=%s", c.namespace), c.oob)
	cmd.WaitDelay = time.Second * 7
	cmd.Cancel = func() error {
		log.Debug(c.ctx, "Sending SIGTERM to console process")
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	log.Info(c.ctx, "Running console")
	ptyf, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("cannot run command: %w", err)
	}
	defer func() { _ = ptyf.Close() }()

	var closeOnce sync.Once
	closeF := func() {
		log.Debug(c.ctx, "Sending SIGHUP to console process")
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
					log.Error(c.ctx, fmt.Errorf("cannot resize console PTY: %w", szErr))
				}
			case <-c.ctx.Done():
				return
			}
		}
	}()

	_ = cmd.Wait()
	log.Info(c.ctx, "Console finished")

	return nil
}

// SetupWithManager sets up the server with the Manager.
func (s *ConsoleServer) SetupWithManager(mgr ctrl.Manager) error {
	s.Client = mgr.GetClient()

	return mgr.Add(s)
}
