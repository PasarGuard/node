package tools

import (
	"os"
)

func ReadFileAsString(filePath string) (string, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(fileBytes), nil
}
