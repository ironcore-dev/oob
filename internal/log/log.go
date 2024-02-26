// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"context"
	"io"

	"github.com/go-logr/logr"
	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
)

func Setup(ctx context.Context, dev, silent bool, writer io.Writer) context.Context {
	var zeroLog zerolog.Logger

	if silent {
		return logr.NewContext(ctx, logr.Discard())
	}

	if dev {
		cw := zerolog.ConsoleWriter{
			Out:           writer,
			TimeFormat:    "2006-01-02 15:04:05 MST",
			FieldsExclude: []string{"v"},
		}
		zeroLog = zerolog.New(cw).Level(zerolog.DebugLevel).With().Timestamp().Logger()
	} else {
		zeroLog = zerolog.New(writer).Level(zerolog.DebugLevel).With().Timestamp().Logger()
	}

	return logr.NewContext(ctx, zerologr.New(&zeroLog))
}

func Info(ctx context.Context, msg string, keysAndValues ...interface{}) {
	logr.FromContextOrDiscard(ctx).Info(msg, keysAndValues...)
}

func Debug(ctx context.Context, msg string, keysAndValues ...interface{}) {
	logr.FromContextOrDiscard(ctx).V(1).Info(msg, keysAndValues...)
}

func Error(ctx context.Context, err error, keysAndValues ...interface{}) {
	logr.FromContextOrDiscard(ctx).Error(err, "", keysAndValues...)
}

func WithValues(ctx context.Context, keysAndValues ...interface{}) context.Context {
	return logr.NewContext(ctx, logr.FromContextOrDiscard(ctx).WithValues(keysAndValues...))
}
