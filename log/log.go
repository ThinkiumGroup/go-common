// Copyright 2020 Thinkium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/lestrrat-go/file-rotatelogs"
	"github.com/sirupsen/logrus"
)

const MaxTxsInLog = 50 // up to 50 transaction information can be displayed in the log

var (
	rootLog    *logrus.Logger
	wrapped    logrus.FieldLogger
	_logLocker sync.RWMutex
)

type EmptyWriter struct{}

func (w *EmptyWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func InitLogWithSuffix(path string, suffix string) {
	_logLocker.Lock()
	defer _logLocker.Unlock()
	writer, err := rotatelogs.New(
		path+"."+suffix+".%Y%m%d",
		rotatelogs.WithMaxAge(time.Duration(86400*30)*time.Second),
		rotatelogs.WithRotationTime(time.Duration(86400)*time.Second),
	)
	if err != nil {
		panic("failed to create rotatelogs: " + path)
	}

	formatter := &logrus.TextFormatter{
		FullTimestamp:   true,
		ForceColors:     true,
		TimestampFormat: time.StampMilli,
	}

	rootLog = &logrus.Logger{
		Out:       &EmptyWriter{},
		Formatter: formatter,
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.DebugLevel,
	}
	rootLog.AddHook(NewFileAndConsoleHook(formatter, writer, os.Stdout,
		logrus.InfoLevel, logrus.WarnLevel, logrus.ErrorLevel))
	wrapped = rootLog
}

func InitLog(path string, nid []byte) {
	var suffix string
	if len(nid) == 0 {
		suffix = "_"
	} else if len(nid) > 5 {
		suffix = fmt.Sprintf("%x", nid[:5])
	} else {
		suffix = fmt.Sprintf("%x", nid)
	}
	InitLogWithSuffix(path, suffix)
}

func init() {
	formatter := &logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.StampMilli,
	}

	rootLog = &logrus.Logger{
		Out:       os.Stdout,
		Formatter: formatter,
		Hooks:     make(logrus.LevelHooks),
		Level:     logrus.DebugLevel,
	}
	wrapped = rootLog
}

// func Logger() *logrus.Logger {
// 	return rootLog
// }

func Debug(msgs ...interface{}) {
	_logLocker.RLock()
	defer _logLocker.RUnlock()

	wrapped.Debug(msgs...)
}

func Debugf(format string, values ...interface{}) {
	_logLocker.RLock()
	defer _logLocker.RUnlock()

	wrapped.Debugf(format, values...)
}

func Info(msgs ...interface{}) {
	_logLocker.RLock()
	defer _logLocker.RUnlock()

	wrapped.Info(msgs...)
}

func Infof(format string, values ...interface{}) {
	_logLocker.RLock()
	defer _logLocker.RUnlock()

	wrapped.Infof(format, values...)
}

func Warn(msgs ...interface{}) {
	_logLocker.RLock()
	defer _logLocker.RUnlock()

	wrapped.Warn(msgs...)
}

func Warnf(format string, values ...interface{}) {
	_logLocker.RLock()
	defer _logLocker.RUnlock()

	wrapped.Warnf(format, values...)
}

func Error(msgs ...interface{}) {
	_logLocker.RLock()
	defer _logLocker.RUnlock()

	wrapped.Error(msgs...)
}

func Errorf(format string, values ...interface{}) {
	_logLocker.RLock()
	defer _logLocker.RUnlock()

	wrapped.Errorf(format, values...)
}

func MustDebugf(logger logrus.FieldLogger, format string, args ...interface{}) {
	if logger == nil {
		Debugf(format, args...)
	} else {
		logger.Debugf(format, args...)
	}
}

func MustInfof(logger logrus.FieldLogger, format string, args ...interface{}) {
	if logger == nil {
		Infof(format, args...)
	} else {
		logger.Infof(format, args...)
	}
}

func MustWarnf(logger logrus.FieldLogger, format string, args ...interface{}) {
	if logger == nil {
		Warnf(format, args...)
	} else {
		logger.Warnf(format, args...)
	}
}

func MustErrorf(logger logrus.FieldLogger, format string, args ...interface{}) {
	if logger == nil {
		Errorf(format, args...)
	} else {
		logger.Errorf(format, args...)
	}
}

func WithFields(fields logrus.Fields) logrus.FieldLogger {
	return rootLog.WithFields(fields)
}

func WithField(vs ...interface{}) logrus.FieldLogger {
	if len(vs) <= 1 {
		return rootLog
	}
	l := len(vs)
	fields := make(logrus.Fields)
	for i := 0; i < l/2; i += 2 {
		k, ok := vs[i].(string)
		if !ok {
			continue
		}
		fields[k] = vs[i+1]
	}
	return rootLog.WithFields(fields)
}

func SetFields(fields logrus.Fields) {
	_logLocker.Lock()
	defer _logLocker.Unlock()

	logger := wrapped.WithFields(fields)
	wrapped = logger
}
