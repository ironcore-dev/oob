// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/ironcore-dev/oob/internal/log"
)

type terminal struct {
	in         *os.File
	out        *os.File
	state      *term.State
	sigs       chan os.Signal
	resizeFunc func(h, w int) error
}

func (t *terminal) prepare(ctx context.Context) error {
	infd := int(t.in.Fd())
	log.WithValues(ctx, "fd", infd)

	if !term.IsTerminal(infd) {
		return fmt.Errorf("input file is not a terminal")
	}

	log.Debug(ctx, "Switching terminal to raw mode")
	var err error
	t.state, err = term.MakeRaw(infd)
	if err != nil {
		return fmt.Errorf("cannot switch terminal to raw mode: %w", err)
	}

	var h, w int
	w, h, err = term.GetSize(infd)
	if err != nil {
		return fmt.Errorf("cannot determine size of terminal: %w", err)
	}
	err = t.resizeFunc(h, w)
	if err != nil {
		return fmt.Errorf("cannot resize console: %w", err)
	}

	t.sigs = make(chan os.Signal, 1)
	signal.Notify(t.sigs, syscall.SIGWINCH)
	go t.handleSigs(ctx)

	return nil
}

func (t *terminal) handleSigs(ctx context.Context) {
	infd := int(t.in.Fd())
	for range t.sigs {
		log.Debug(ctx, "Received SIGWINCH, resizing console")
		w, h, err := term.GetSize(infd)
		if err != nil {
			log.Error(ctx, fmt.Errorf("cannot determine size of terminal: %w", err))
		}
		err = t.resizeFunc(h, w)
		if err != nil {
			log.Error(ctx, fmt.Errorf("cannot resize console: %w", err))
		}
	}
}

func (t *terminal) restore(ctx context.Context) error {
	signal.Stop(t.sigs)
	close(t.sigs)

	// TODO: better reset, see https://man7.org/linux/man-pages/man1/tset.1.html
	log.Debug(ctx, "Resetting terminal")
	err := term.Restore(int(t.in.Fd()), t.state)
	if err != nil {
		return fmt.Errorf("cannot restore teminal to original state: %w", err)
	}

	return nil
}
