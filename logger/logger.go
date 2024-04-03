package logger

import (
	"log"
	"os"
)

var (
	Info     *log.Logger
	Error    *log.Logger
	Debug    *log.Logger
	Warning  *log.Logger
	Critical *log.Logger
)

func InfoLog(message string) {
	Info.Println(message)
}

func ErrorLog(message string, error error) {
	Error.Printf(message, error)
}

func DebugLog(message string) {
	Debug.Println(message)
}

func WarningLog(message string) {
	Warning.Println(message)
}

func CriticalLog(message string) {
	Critical.Println(message)
}

func InitLogger() {
	infoHandle := os.Stdout
	errorHandle := os.Stderr
	debugHandle := os.Stdout
	warningHandle := os.Stdout
	criticalHandle := os.Stderr

	Info = log.New(infoHandle, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	Error = log.New(errorHandle, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	Debug = log.New(debugHandle, "Debug: ", log.Ldate|log.Ltime|log.Lshortfile)
	Warning = log.New(warningHandle, "Warning: ", log.Ldate|log.Ltime|log.Lshortfile)
	Critical = log.New(criticalHandle, "Critical: ", log.Ldate|log.Ltime|log.Lshortfile)

}
