package log

import (
	"context"
	"os"

	"github.com/go-logr/logr"
	"github.com/go-logr/zerologr"
	"github.com/rs/zerolog"
)

func Setup(ctx context.Context, dev bool) context.Context {
	var zeroLog zerolog.Logger

	if dev {
		cw := zerolog.ConsoleWriter{
			Out:           os.Stderr,
			TimeFormat:    "2006-01-02 15:04:05 MST",
			FieldsExclude: []string{"v"},
		}
		zeroLog = zerolog.New(cw).Level(zerolog.DebugLevel).With().Timestamp().Logger()
	} else {
		zeroLog = zerolog.New(os.Stderr).Level(zerolog.DebugLevel).With().Timestamp().Logger()
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
