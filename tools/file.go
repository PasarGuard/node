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

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// StringToTempFile writes the given string to a temporary file.
func StringToTempFile(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "node_temp_*.pem")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err = tmpFile.WriteString(content); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}
