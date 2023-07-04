package log

import (
	"fmt"
	"sync"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"github.com/sirupsen/logrus"
)

var (
	ccLog        *logrus.Logger
	ccLogLock    sync.RWMutex
	createCCOnce sync.Once
)

func InitCheckLog(path string, nid []byte) {
	createCCOnce.Do(func() {
		ccLogLock.Lock()
		defer ccLogLock.Unlock()
		checkLogFile := path + ".check." + fmt.Sprintf("%x", nid[:5]) + ".%Y"
		checkWriter, err := rotatelogs.New(checkLogFile,
			rotatelogs.WithMaxAge(-1), rotatelogs.WithRotationTime(time.Hour*24*365))
		if err != nil {
			rootLog.Errorf("initial CashCheck log %s failed: %v", checkLogFile, err)
			return
		}
		formatter := &logrus.TextFormatter{
			FullTimestamp:   true,
			ForceColors:     true,
			TimestampFormat: time.StampMilli,
		}
		ccLog = &logrus.Logger{
			Out:       checkWriter,
			Formatter: formatter,
			Level:     logrus.DebugLevel,
		}
	},
	)
}

func CCDebug(msgs ...interface{}) {
	ccLogLock.RLock()
	defer ccLogLock.RUnlock()
	ccLog.Debug(msgs...)
}

func CCDebugf(format string, values ...interface{}) {
	ccLogLock.RLock()
	defer ccLogLock.RUnlock()
	ccLog.Debugf(format, values...)
}

func CCInfo(msgs ...interface{}) {
	ccLogLock.RLock()
	defer ccLogLock.RUnlock()
	ccLog.Info(msgs...)
}

func CCInfof(format string, values ...interface{}) {
	ccLogLock.RLock()
	defer ccLogLock.RUnlock()
	ccLog.Infof(format, values...)
}

func CCWarn(msgs ...interface{}) {
	ccLogLock.RLock()
	defer ccLogLock.RUnlock()
	ccLog.Warn(msgs...)
}

func CCWarnf(format string, values ...interface{}) {
	ccLogLock.RLock()
	defer ccLogLock.RUnlock()
	ccLog.Warnf(format, values...)
}

func CCError(msgs ...interface{}) {
	ccLogLock.RLock()
	defer ccLogLock.RUnlock()
	ccLog.Error(msgs...)
}

func CCErrorf(format string, values ...interface{}) {
	ccLogLock.RLock()
	defer ccLogLock.RUnlock()
	ccLog.Errorf(format, values...)
}

func CCWithFields(fields logrus.Fields) logrus.FieldLogger {
	ccLogLock.RLock()
	defer ccLogLock.RUnlock()
	return ccLog.WithFields(fields)
}
