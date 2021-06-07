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
	"time"

	"github.com/lestrrat-go/file-rotatelogs"
	"github.com/sirupsen/logrus"
)

const MaxTxsInLog = 50 // up to 50 transaction information can be displayed in the log

var (
	rootLog *logrus.Logger
)

type EmptyWriter struct{}

func (w *EmptyWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func InitLog(path string, nid []byte) {
	writer, err := rotatelogs.New(
		path+"."+fmt.Sprintf("%x", nid[:5])+".%Y%m%d",
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
}

func Debug(msgs ...interface{}) {
	rootLog.Debug(msgs)
}

func Debugf(format string, values ...interface{}) {
	rootLog.Debugf(format, values...)
}

func Info(msgs ...interface{}) {
	rootLog.Info(msgs)
}

func Infof(format string, values ...interface{}) {
	rootLog.Infof(format, values...)
}

func Warn(msgs ...interface{}) {
	rootLog.Warn(msgs)
}

func Warnf(format string, values ...interface{}) {
	rootLog.Warnf(format, values...)
}

func Error(msgs ...interface{}) {
	rootLog.Error(msgs)
}

func Errorf(format string, values ...interface{}) {
	rootLog.Errorf(format, values...)
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
