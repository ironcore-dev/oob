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

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	ipamv1alpha1 "github.com/onmetal/ipam/api/v1alpha1"
	computev1alpha1 "github.com/onmetal/onmetal-api/api/compute/v1alpha1"
	oobv1alpha1 "github.com/onmetal/oob-operator/api/v1alpha1"
	"github.com/onmetal/oob-operator/controllers"
	"github.com/onmetal/oob-operator/log"
	"github.com/onmetal/oob-operator/servers"
)

func usage() {
	name := filepath.Base(os.Args[0])
	_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [--option]...\n", name)
	_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
	pflag.PrintDefaults()
}

func exitUsage(err error) {
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s: %s\n", filepath.Base(os.Args[0]), err)
	}
	pflag.Usage()
	os.Exit(2)
}

type params struct {
	dev                    bool
	leaderElect            bool
	healthProbeBindAddress string
	metricsBindAddress     string
	kubeconfig             string
	namespace              string
	macPrefixes            string
	credentialsExpBuffer   time.Duration
	shutdownTimeout        time.Duration
	consoleServerCert      string
	consoleServerKey       string
}

func parseCmdLine() params {
	pflag.Usage = usage
	pflag.ErrHelp = nil
	pflag.CommandLine = pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	pflag.Bool("dev", false, "Log human-readable messages at debug level.")
	pflag.Bool("leader-elect", false, "Enable leader election for controller manager to ensure there is only one active controller manager.")
	pflag.String("health-probe-bind-address", "", "The address and port for the probe endpoint.")
	pflag.String("metrics-bind-address", "0", "The address and port for the metrics endpoint.")
	pflag.String("kubeconfig", "", "Use a kubeconfig to run out of cluster.")
	pflag.String("namespace", "", "Limit monitoring to a specific namespace.")
	pflag.String("mac-prefixes", "macPrefixes.yaml", "Read MAC address prefixes from the specified file.")
	pflag.Duration("credentials-exp-buffer", 125*time.Hour, "Renew expiring credentials this long before they are set to expire expire. See https://golang.org/pkg/time/#ParseDuration")
	pflag.Duration("shutdown-timeout", 5*time.Minute, "Wait this long before issuing an immediate shutdown, if graceful shutdown has not succeeded. See https://golang.org/pkg/time/#ParseDuration")
	pflag.String("console-server-cert", "", "Use a TLS certificate for the console server. If not set, do not start the console server.")
	pflag.String("console-server-key", "", "Use a TLS key for the console server. If not set, do not start the console server.")

	var help bool
	pflag.BoolVarP(&help, "help", "h", false, "Show this help message.")
	utilruntime.Must(viper.BindPFlags(pflag.CommandLine))
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	err := pflag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		exitUsage(err)
	}
	if help {
		exitUsage(nil)
	}

	return params{
		dev:                    viper.GetBool("dev"),
		leaderElect:            viper.GetBool("leader-elect"),
		healthProbeBindAddress: viper.GetString("health-probe-bind-address"),
		metricsBindAddress:     viper.GetString("metrics-bind-address"),
		kubeconfig:             viper.GetString("kubeconfig"),
		namespace:              viper.GetString("namespace"),
		macPrefixes:            viper.GetString("mac-prefixes"),
		credentialsExpBuffer:   viper.GetDuration("credentials-exp-buffer"),
		shutdownTimeout:        viper.GetDuration("shutdown-timeout"),
		consoleServerCert:      viper.GetString("console-server-cert"),
		consoleServerKey:       viper.GetString("console-server-key"),
	}
}

func main() {
	p := parseCmdLine()

	var exitCode int
	defer func() { os.Exit(exitCode) }()

	ctx, stop := signal.NotifyContext(log.Setup(context.Background(), p.dev, false, os.Stderr), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)
	defer stop()
	log.Info(ctx, "Starting OOB operator")

	defer func() { log.Info(ctx, "Exiting", "exitCode", exitCode) }()

	l := logr.FromContextOrDiscard(ctx)
	klog.SetLogger(l)
	ctrl.SetLogger(l)

	scheme := runtime.NewScheme()
	utilruntime.Must(kscheme.AddToScheme(scheme))
	utilruntime.Must(ipamv1alpha1.AddToScheme(scheme))
	utilruntime.Must(oobv1alpha1.AddToScheme(scheme))
	utilruntime.Must(computev1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme

	if p.namespace == "" {
		ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil && !os.IsNotExist(err) {
			log.Error(ctx, fmt.Errorf("cannot determine in-cluster namespace: %w", err))
			exitCode = 1
			return
		}
		p.namespace = string(ns)
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		BaseContext: func() context.Context {
			return ctx
		},
		Scheme:                 scheme,
		LeaderElection:         p.leaderElect,
		LeaderElectionID:       "125e56fc.onmetal.de",
		HealthProbeBindAddress: p.healthProbeBindAddress,
		MetricsBindAddress:     p.metricsBindAddress,
	})
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot create manager: %w", err))
		exitCode = 1
		return
	}

	ipReconciler := &controllers.IPReconciler{
		Namespace: p.namespace,
	}
	err = ipReconciler.SetupWithManager(mgr)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot create controller: %w", err), "controller", "IP")
		exitCode = 1
		return
	}

	oobReconciler := &controllers.OOBReconciler{
		Namespace:            p.namespace,
		CredentialsExpBuffer: p.credentialsExpBuffer,
		ShutdownTimeout:      p.shutdownTimeout,
	}
	if p.macPrefixes != "" {
		err = oobReconciler.LoadMACPrefixes(ctx, p.macPrefixes)
		if err != nil {
			log.Error(ctx, fmt.Errorf("cannot read MAC prefixes: %w", err), "controller", "OOB")
			exitCode = 1
			return
		}
	}
	err = oobReconciler.SetupWithManager(mgr)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot create controller: %w", err), "controller", "OOB")
		exitCode = 1
		return
	}

	if p.consoleServerCert != "" && p.consoleServerKey != "" {
		consoleServer := &servers.ConsoleServer{
			Address: ":12319",
			TLSCert: p.consoleServerCert,
			TLSKey:  p.consoleServerKey,
		}
		err = consoleServer.SetupWithManager(mgr)
		if err != nil {
			log.Error(ctx, fmt.Errorf("cannot create server: %w", err), "server", "console")
			exitCode = 1
			return
		}
	}

	//+kubebuilder:scaffold:builder

	err = mgr.AddHealthzCheck("health", healthz.Ping)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot set up health check: %w", err))
		exitCode = 1
		return
	}

	err = mgr.AddReadyzCheck("check", healthz.Ping)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot set up ready check: %w", err))
		exitCode = 1
		return
	}

	log.Info(ctx, "Starting manager")
	err = mgr.Start(ctx)
	if err != nil {
		log.Error(ctx, fmt.Errorf("cannot start manager: %w", err))
		exitCode = 1
		return
	}
}
