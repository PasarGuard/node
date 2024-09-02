package logger

import (
	"fmt"
	"log"
	"marzban-node/config"
	"os"
	"path/filepath"
	"regexp"
)

var (
	re            *regexp.Regexp
	accessLogFile *os.File
	errorLogFile  *os.File
	accessLogger  *log.Logger
	errorLogger   *log.Logger
)

func init() {
	pattern := `^(\d{4}/\d{2}/\d{2}) (\d{2}:\d{2}:\d{2}) (\[.*?\]) (.*)$`

	// Compile the regex
	re = regexp.MustCompile(pattern)
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

func SetLogFile(accessPath, errorPath string) {
	// Close any previously opened files
	if accessLogFile != nil {
		_ = accessLogFile.Close()
		accessLogFile = nil
	}
	if errorLogFile != nil {
		_ = errorLogFile.Close()
		errorLogFile = nil
	}

	var err error

	accessLogFile, err = openLogFile(accessPath)
	if err != nil {
		Error("Error opening access log file: ", err)
		Warning("Access log will not be recorded on file")
		accessLogger = nil
	} else if accessLogFile != nil {
		// Create the access logger
		accessLogger = log.New(accessLogFile, "", 0)
	} else {
		accessLogger = nil
	}

	errorLogFile, err = openLogFile(errorPath)
	if err != nil {
		Error("Error opening error log file: ", err)
		Warning("Error log will not be recorded on file")
		errorLogger = nil
	} else if errorLogFile != nil {
		// Create the error logger
		errorLogger = log.New(errorLogFile, "", 0)
	} else {
		errorLogger = nil
	}
}

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
)

func Info(message ...any) {
	formattedLog := fmt.Sprintf("%s[Info] %s %s", colorGreen, colorReset, message)
	log.Println(formattedLog)
}

func Api(message ...any) {
	formattedLog := fmt.Sprintf("%s[Api] %s %s", colorCyan, colorReset, message)
	log.Println(formattedLog)
}

func Error(message ...any) {
	formattedLog := fmt.Sprintf("%s[Error]%s %s", colorRed, colorReset, message)
	log.Println(formattedLog)
}

func Debug(message ...any) {
	formattedLog := fmt.Sprintf("%s[Debug] %s %s", colorBlue, colorReset, message)
	log.Println(formattedLog)
}

func Warning(message ...any) {
	formattedLog := fmt.Sprintf("%s[Warning] %s %s", colorYellow, colorReset, message)
	log.Println(formattedLog)
}

func Critical(message ...any) {
	formattedLog := fmt.Sprintf("%s[Critical] %s %s", colorMagenta, colorReset, message)
	log.Println(formattedLog)
}

func DetectLogType(newLog string) {
	level := ""
	message := ""

	// Find the matches
	matches := re.FindStringSubmatch(newLog)
	if len(matches) > 3 {
		level = matches[3]
		message = matches[4]
	} else {
		message = newLog
	}

	if config.Debug {
		switch level {
		case "Debug":
			Debug(message)
		case "Info":
			Info(message)
		case "Warning":
			Warning(message)
		case "Error":
			Error(message)
		default:
			Debug(message)
		}
	}

	switch level {
	case "Error":
		if errorLogger != nil {
			errorLogger.Println(newLog)
		}
	default:
		if accessLogger != nil {
			accessLogger.Println(newLog)
		}
	}
}
