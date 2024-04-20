package logger

import (
	"fmt"
	"log"
)

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
)

func InfoLog(message string) {
	formattedLog := fmt.Sprintf("%s[Info] %s %s", colorGreen, colorReset, message)
	log.Println(formattedLog)
}

func ApiLog(message string) {
	formattedLog := fmt.Sprintf("%s[Api] %s %s", colorCyan, colorReset, message)
	log.Println(formattedLog)
}

func ErrorLog(message string, err error) {
	formattedLog := fmt.Sprintf("%s[Error]%s %s %s", colorRed, colorReset, message, err)
	log.Println(formattedLog)
}

func DebugLog(message string) {
	formattedLog := fmt.Sprintf("%s[Debug] %s %s", colorBlue, colorReset, message)
	fmt.Println(formattedLog)
}

func WarningLog(message string) {
	formattedLog := fmt.Sprintf("%s[Warning] %s %s", colorYellow, colorReset, message)
	log.Println(formattedLog)
}

func CriticalLog(message string) {
	formattedLog := fmt.Sprintf("%s[Info] %s %s", colorMagenta, colorReset, message)
	log.Println(formattedLog)
}
