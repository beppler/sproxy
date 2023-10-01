package sproxy

type Configuration struct {
}

func NewConfiguration() (*Configuration, error) {
	return &Configuration{}, nil
}
