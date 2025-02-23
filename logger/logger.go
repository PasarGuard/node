package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

var (
	outputLogs    = false
	accessLogFile *os.File
	errorLogFile  *os.File
	accessLogger  *log.Logger
	errorLogger   *log.Logger
	mutex         sync.Mutex
)

func SetOutputMode(mode bool) {
	mutex.Lock()
	defer mutex.Unlock()
	outputLogs = mode
}

func openLogFile(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}

	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil { // Creates all necessary parent directories
		return nil, err
	}

	// Try to open the file, create if not exists, and append to it
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func SetLogFile(accessPath, errorPath string) error {
	mutex.Lock()
	defer mutex.Unlock()

	var err error

	if accessLogFile, err = openLogFile(accessPath); err != nil {
		return fmt.Errorf("failed to open access log: %w", err)
	}
	if accessLogFile != nil {
		accessLogger = log.New(accessLogFile, "", log.LstdFlags)
	}

	if errorLogFile, err = openLogFile(errorPath); err != nil {
		return fmt.Errorf("failed to open error log: %w", err)
	}
	if errorLogFile != nil {
		errorLogger = log.New(errorLogFile, "", log.LstdFlags)
	}

	return nil
}

const (
	LogDebug    = "Debug"
	LogInfo     = "Info"
	LogWarning  = "Warning"
	LogError    = "Error"
	LogCritical = "Critical"
)

func logMessage(logger *log.Logger, level, message string) {
	if logger == nil {
		return
	}
	logger.Printf("[%s] %s\n", level, message)
}

func Log(level, message string) {
	formattedMessage := fmt.Sprintf("[%s] %s", level, message)
	switch level {
	case LogError, LogCritical:
		logMessage(errorLogger, level, message)
	default:
		logMessage(accessLogger, level, message)
	}
	if outputLogs {
		log.Println(formattedMessage)
	}
}
