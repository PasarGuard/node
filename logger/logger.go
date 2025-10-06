package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

type LogLevel string

const (
	LogDebug    LogLevel = "Debug"
	LogInfo     LogLevel = "Info"
	LogWarning  LogLevel = "Warning"
	LogError    LogLevel = "Error"
	LogCritical LogLevel = "Critical"
)

type Logger struct {
	outputLogs    bool
	accessLogFile *os.File
	errorLogFile  *os.File
	accessLogger  *log.Logger
	errorLogger   *log.Logger
	mu            sync.RWMutex
}

func New(outputLogs bool) *Logger {
	return &Logger{
		outputLogs: outputLogs,
	}
}

func openLogFile(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}

	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Try to open the file, create if not exists, and append to it
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (l *Logger) SetLogFile(accessPath, errorPath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var err error

	if l.accessLogFile, err = openLogFile(accessPath); err != nil {
		return fmt.Errorf("failed to open access log: %w", err)
	}
	if l.accessLogFile != nil {
		l.accessLogger = log.New(l.accessLogFile, "", 0)
	}

	if l.errorLogFile, err = openLogFile(errorPath); err != nil {
		return fmt.Errorf("failed to open error log: %w", err)
	}
	if l.errorLogFile != nil {
		l.errorLogger = log.New(l.errorLogFile, "", 0)
	}

	return nil
}

func (l *Logger) Log(level LogLevel, message string) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	switch level {
	case LogError, LogCritical:
		if l.errorLogger != nil {
			l.errorLogger.Println(message)
		}
	default:
		if l.accessLogger != nil {
			l.accessLogger.Println(message)
		}
	}

	if l.outputLogs {
		fmt.Println(message)
	}
}

func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.accessLogFile != nil {
		l.accessLogFile.Close()
		l.accessLogFile = nil
	}
	if l.errorLogFile != nil {
		l.errorLogFile.Close()
		l.errorLogFile = nil
	}
}
