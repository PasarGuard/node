package backend

type Config interface {
	ToJSON() (string, error)
	ApplyAPI(int) error
	RemoveLogFiles() (string, string)
}

type ConfigKey struct{}

type UsersKey struct{}
