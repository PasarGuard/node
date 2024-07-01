package logger

import (
	"fmt"
	"log"
	"regexp"
)

var re *regexp.Regexp

func init() {
	pattern := `^(\d{4}/\d{2}/\d{2}) (\d{2}:\d{2}:\d{2}) (\[.*?\]) (.*)$`

	// Compile the regex
	re = regexp.MustCompile(pattern)
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
	// Find the matches
	matches := re.FindStringSubmatch(newLog)

	if len(matches) > 3 {
		level := matches[3]
		message := matches[4]

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

	} else if newLog != "" {
		Debug(newLog)
	}
}
