// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"

	"github.com/ironcore-dev/oob/internal/log"
)

type consoleSpec struct {
	typ      string
	host     string
	user     string
	password string
	command  []string
}

type console struct {
	consoleSpec
	resizeImpl func() error
	h          int
	w          int
}

func (c *console) run(ctx context.Context, in io.Reader, out io.WriteCloser) error {
	if len(c.command) > 0 {
		return c.runLocal(ctx, in, out, nil, nil, nil, 1)
	}

	ctx = log.WithValues(ctx, "type", c.typ)
	switch c.typ {

	case "ssh":
		return c.runSSH(ctx, in, out, nil, nil, nil, 1)

	case "ssh-lenovo":
		return c.runSSH(ctx, in, out, []byte("console 1\n"), []byte{27, '('}, []byte{'\n', 's', 'y', 's', 't', 'e', 'm', '>'}, 2)

	case "ipmi":
		return c.runIPMI(ctx, in, out, nil, []byte{27, '('}, nil, 1)

	case "telnet":
		return c.runTelnet(ctx, in, out, nil, []byte{94, ']'}, nil, 1)

	default:
		return fmt.Errorf("unsupported console type: %s", c.typ)
	}
}

func (c *console) runLocal(ctx context.Context, in io.Reader, out io.WriteCloser, cmd, escIn, escOut []byte, escOutOrd int) error {
	localcmd := exec.Command(c.command[0], c.command[1:]...)

	log.Debug(ctx, "Starting local process", "h", c.h, "w", c.w)
	ptyf, err := pty.StartWithSize(localcmd, &pty.Winsize{
		Rows: uint16(c.h),
		Cols: uint16(c.w),
	})
	if err != nil {
		return fmt.Errorf("cannot run %s: %w", c.command[0], err)
	}
	defer func() { _ = ptyf.Close() }()

	c.resizeImpl = func() error {
		log.Debug(ctx, "Resizing PTY", "h", c.h, "w", c.w)
		return pty.Setsize(ptyf, &pty.Winsize{
			Rows: uint16(c.h),
			Cols: uint16(c.w),
		})
	}

	closed := func() {
		_ = localcmd.Process.Signal(syscall.SIGHUP)
	}
	err = c.start(ctx, in, out, ptyf, ptyf, closed, cmd, escIn, escOut, escOutOrd)
	if err != nil {
		return fmt.Errorf("error while running %s: %w", c.command[0], err)
	}

	_ = localcmd.Wait()
	c.resizeImpl = nil
	log.Debug(ctx, "Local proccess has exited")

	return nil
}

func (c *console) runSSH(ctx context.Context, in io.Reader, out io.WriteCloser, cmd, escIn, escOut []byte, escOutOrd int) error {
	port := "22"
	conf := ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            c.user,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.password),
		},
	}
	ctx = log.WithValues(ctx, "host", c.host, "port", port, "user", c.user)

	log.Debug(ctx, "Establishing SSH connection")
	var err error
	var client *ssh.Client
	client, err = ssh.Dial("tcp", net.JoinHostPort(c.host, port), &conf)
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer func() {
		_ = client.Close()
	}()

	var session *ssh.Session
	session, err = client.NewSession()
	if err != nil {
		return fmt.Errorf("cannot create session: %w", err)
	}
	defer func() {
		_ = session.Close()
	}()

	var sshStdin io.WriteCloser
	sshStdin, err = session.StdinPipe()
	if err != nil {
		return fmt.Errorf("cannot open stdin pipe: %w", err)
	}
	defer func() {
		_ = sshStdin.Close()
	}()

	var sshStdout io.Reader
	sshStdout, err = session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("cannot open stdout pipe: %w", err)
	}

	envTerm := os.Getenv("TERM")
	if envTerm == "" {
		envTerm = "xterm-256color"
	}

	log.Debug(ctx, "Requesting PTY", "term", envTerm, "h", c.h, "w", c.w)
	err = session.RequestPty(envTerm, c.h, c.w, ssh.TerminalModes{ssh.ECHO: 0})
	if err != nil {
		return fmt.Errorf("cannot request PTY: %w", err)
	}

	err = session.Shell()
	if err != nil {
		return fmt.Errorf("cannot start remote shell: %w", err)
	}

	c.resizeImpl = func() error {
		log.Debug(ctx, "Resizing PTY", "h", c.h, "w", c.w)
		return session.WindowChange(c.h, c.w)
	}

	closed := func() {
		_ = session.Close()
	}
	err = c.start(ctx, in, out, sshStdin, sshStdout, closed, cmd, escIn, escOut, escOutOrd)
	if err != nil {
		return fmt.Errorf("error while running SSH session: %w", err)
	}

	_ = session.Wait()
	c.resizeImpl = nil
	log.Debug(ctx, "SSH session has ended")

	return nil
}

func (c *console) runIPMI(ctx context.Context, in io.Reader, out io.WriteCloser, cmd, escIn, escOut []byte, escOutOrd int) error {
	port := "623"
	ctx = log.WithValues(ctx, "host", c.host, "port", port, "user", c.user)

	c.command = []string{"/usr/sbin/ipmi-console", "-h", c.host, "-u", c.user, "-p", c.password}
	return c.runLocal(ctx, in, out, cmd, escIn, escOut, escOutOrd)
}

func (c *console) runTelnet(ctx context.Context, in io.Reader, out io.WriteCloser, cmd, escIn, escOut []byte, escOutOrd int) error {
	port := "23"
	ctx = log.WithValues(ctx, "host", c.host, "port", port, "user", c.user)

	c.command = []string{"/usr/bin/telnet", c.host}
	return c.runLocal(ctx, in, out, cmd, escIn, escOut, escOutOrd)
}

func (c *console) start(ctx context.Context, ttyIn io.Reader, ttyOut, ptyIn io.WriteCloser, ptyOut io.Reader, closed func(), cmd, escIn, escOut []byte, escOutOrd int) error {
	log.Debug(ctx, "Starting console")
	if cmd != nil {
		_, err := ptyIn.Write(cmd)
		if err != nil {
			return fmt.Errorf("cannot send initial command: %w", err)
		}
	}

	var closeOnce sync.Once
	go func() {
		_, _ = io.Copy(ptyIn, newMonitoringReader(ttyIn, escIn, 1))
		_ = ptyIn.Close()
		if closed != nil {
			closeOnce.Do(closed)
		}
	}()
	go func() {
		_, _ = io.Copy(ttyOut, newMonitoringReader(ptyOut, escOut, escOutOrd))
		_ = ttyOut.Close()
		if closed != nil {
			closeOnce.Do(closed)
		}
	}()

	return nil
}

func (c *console) resize(h, w int) error {
	c.h, c.w = h, w
	if c.resizeImpl == nil {
		return nil
	}
	return c.resizeImpl()
}

type monitoringReader struct {
	source  io.Reader
	canary  []byte
	ordinal int
	ncanary int
	nprev   int
}

func newMonitoringReader(reader io.Reader, canary []byte, ordinal int) *monitoringReader {
	return &monitoringReader{source: reader, canary: canary, ordinal: ordinal, ncanary: len(canary)}
}

func (r *monitoringReader) Read(p []byte) (int, error) {
	if r.ordinal <= 0 {
		return 0, io.EOF
	}

	n, err := r.source.Read(p)

	if r.ncanary == 0 {
		return n, err
	}

	if n > 0 {
		buf := p[:n]

		off := 0
		if r.nprev > 0 {
			match := true
			var i int
			for i = 0; i < min(n, r.ncanary-r.nprev); i++ {
				if buf[i] != r.canary[r.nprev+i] {
					match = false
					break
				}
			}
			if match {
				if i == r.ncanary-r.nprev {
					r.ordinal--
					if r.ordinal == 0 {
						return i, err
					}
					off = i
				} else {
					r.nprev += i
					return n, err
				}
			}
			r.nprev = 0
		}

		i := bytes.Index(buf[off:], r.canary)
		for i >= 0 {
			r.ordinal--
			if r.ordinal == 0 {
				return off + i + r.ncanary, err
			}
			off += i + r.ncanary
			i = bytes.Index(buf[off:], r.canary)
		}

		for i = min(r.ncanary-1, n); i > 0; i-- {
			if bytes.Equal(buf[n-i:], r.canary[:i]) {
				r.nprev = i
				break
			}
		}
	}

	return n, err
}
