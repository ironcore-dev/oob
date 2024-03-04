// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/go-logr/logr"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"k8s.io/klog/v2"

	"github.com/ironcore-dev/oob/internal/log"
)

func usage() {
	name := filepath.Base(os.Args[0])
	_, _ = fmt.Fprintf(os.Stderr, "Usage: %s [--option]... oob\n       %s [--option]... -c command...\n       %s [--option]... --connect=remote\n", name, name, name)
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
	dev        bool
	silent     bool
	kubeconfig string
	namespace  string
	oob        string
	command    []string
}

func parseCmdLine() params {
	pflag.Usage = usage
	pflag.ErrHelp = nil
	pflag.CommandLine = pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	pflag.Bool("dev", false, "Log human-readable messages at debug level.")
	pflag.Bool("silent", false, "Log nothing. Overrides dev.")
	pflag.String("kubeconfig", "", "Use the specified kubeconfig file.")
	pflag.StringP("namespace", "n", "", "Operate in a specific namespace.")
	pflag.BoolP("command", "c", false, "Run a local command instead of retrieving an OOB from Kubernetes.")

	var help bool
	pflag.BoolVarP(&help, "help", "h", false, "Show this help message.")
	err := viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		exitUsage(err)
	}
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()
	err = pflag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		exitUsage(err)
	}
	if help {
		exitUsage(nil)
	}

	p := params{
		dev:        viper.GetBool("dev"),
		silent:     viper.GetBool("silent"),
		kubeconfig: viper.GetString("kubeconfig"),
		namespace:  viper.GetString("namespace"),
	}

	if viper.GetBool("command") {
		p.command = pflag.Args()
		if len(p.command) == 0 {
			exitUsage(fmt.Errorf("command cannot be empty"))
		}
	} else {
		p.oob = pflag.Arg(0)
	}

	if p.oob == "" && len(p.command) == 0 {
		exitUsage(fmt.Errorf("an OOB, a command, or a connection must be specified"))
	}

	return p
}

func main() {
	p := parseCmdLine()

	var exitCode int
	defer func() { os.Exit(exitCode) }()

	ctx, stop := signal.NotifyContext(log.Setup(context.Background(), p.dev, p.silent, os.Stderr), syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGHUP)
	defer stop()
	log.Info(ctx, "Starting console")

	l := logr.FromContextOrDiscard(ctx)
	klog.SetLogger(l)

	var c consoleSpec
	var err error
	if len(p.command) > 0 {
		c.command = p.command
	} else {
		if p.oob != "" && p.namespace == "" {
			p.namespace, err = getInClusterNamespace()
			if err != nil {
				log.Error(ctx, err)
				exitCode = 1
				return
			}
			if p.namespace != "" {
				log.Debug(ctx, "Using in-cluster namespace", "namespace", p.namespace)
			}
		}

		log.Debug(ctx, "Setting up Kubernetes connection")
		var clients k8sClients
		clients, err = newK8sClients(p.kubeconfig)
		if err != nil {
			log.Error(ctx, err)
			exitCode = 1
			return
		}

		log.Debug(ctx, "Retrieving console parameters")
		c, err = getConsoleSpec(ctx, clients, p.namespace, p.oob)
		if err != nil {
			log.Error(ctx, err)
			exitCode = 1
			return
		}
	}

	log.Debug(ctx, "Running in local mode")
	err = runLocal(ctx, c)
	if err != nil {
		log.Error(ctx, err)
		exitCode = 1
		return
	}
}

func runLocal(ctx context.Context, cs consoleSpec) error {
	ctx = log.WithValues(ctx, "type", cs.typ, "host", cs.host, "user", cs.user)
	c := console{consoleSpec: cs}
	t := terminal{
		in:         os.Stdin,
		out:        os.Stdout,
		resizeFunc: c.resize,
	}

	err := t.prepare(ctx)
	if err != nil {
		return fmt.Errorf("cannot prepare terminal: %w", err)
	}
	defer func() { _ = t.restore(ctx) }()

	err = c.run(ctx, os.Stdin, os.Stdout)
	if err != nil {
		return fmt.Errorf("error while running console: %w", err)
	}

	return nil
}
