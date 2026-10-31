// Package logrus is a minimal stub of github.com/sirupsen/logrus for testing.
package logrus

type Fields map[string]interface{}

type Entry struct{}

func (e *Entry) Info(args ...interface{}) {}

func WithFields(fields Fields) *Entry { return &Entry{} }

func Infof(format string, args ...interface{}) {}

func Info(args ...interface{}) {}
