package service

func NewService() (*Service, error) {

	s := new(Service)
	err := s.Init()
	if err != nil {
		return nil, err
	}

	return s, nil
}
