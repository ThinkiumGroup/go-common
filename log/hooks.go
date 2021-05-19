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
	"io"
	"sync"

	"github.com/sirupsen/logrus"
)

type FileAndConsoleHook struct {
	formatter     logrus.Formatter
	logfile       io.Writer                 // Writer of the log file, all levels of the log must be written
	consoleWriter io.Writer                 // Writer of console, writes the log of the specified level
	consoleLevels map[logrus.Level]struct{} // levels write to console
	lock          sync.Mutex
	enabled       bool
}

func NewFileAndConsoleHook(formatter logrus.Formatter, logWriter io.Writer,
	console io.Writer, consoleLevels ...logrus.Level) *FileAndConsoleHook {
	if formatter == nil {
		formatter = &logrus.TextFormatter{}
	}
	if logWriter == nil && console == nil {
		return &FileAndConsoleHook{formatter: formatter, enabled: false}
	}

	levels := make(map[logrus.Level]struct{})
	for _, l := range consoleLevels {
		levels[l] = struct{}{}
	}
	return &FileAndConsoleHook{
		formatter:     formatter,
		logfile:       logWriter,
		consoleWriter: console,
		consoleLevels: levels,
		enabled:       true,
	}
}

func (m *FileAndConsoleHook) Fire(entry *logrus.Entry) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if !m.enabled {
		return nil
	}

	msg, err := m.formatter.Format(entry)
	if err != nil {
		return err
	}

	if m.logfile != nil {
		_, err = m.logfile.Write(msg)
		if err != nil {
			return err
		}
	}

	if m.consoleWriter != nil {
		_, exist := m.consoleLevels[entry.Level]
		if exist {
			_, err = m.consoleWriter.Write(msg)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *FileAndConsoleHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
