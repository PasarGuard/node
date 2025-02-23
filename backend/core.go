package backend

type Core interface {
	GetVersion() string
	Started() bool
	GetLogs() chan string
}
