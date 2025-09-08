package logger

import (
	"fmt"
	"log"
	"os"
)

var debugEnabled bool = false

func Init(debug bool) {
	debugEnabled = debug
}

func logWithLevel(level string, format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	log.Printf("level=%s %q", level, msg)
}

func Debug(format string, v ...interface{}) {
	if debugEnabled {
		logWithLevel("debug", format, v...)
	}
}

func Info(format string, v ...interface{}) {
	logWithLevel("info", format, v...)
}

func Warn(format string, v ...interface{}) {
	logWithLevel("warn", format, v...)
}

func Error(format string, v ...interface{}) {
	logWithLevel("error", format, v...)
}

func Fatal(format string, v ...interface{}) {
	logWithLevel("fatal", format, v...)
	os.Exit(1)
}
