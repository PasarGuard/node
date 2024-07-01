package tools

import "io/ioutil"

func ReadFileAsString(filePath string) (string, error) {
	fileBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(fileBytes), nil
}
