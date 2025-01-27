package storage

type Storage interface{}

type Store struct{}

func (s *Store) Get(st Storage) {}

func (s *Store) Set(st Storage) {}

func (s *Store) Del(st Storage) {}
