package store

import (
	"errors"
	"time"

	"authpilot/server/internal/domain"
)

var ErrNotFound = errors.New("not found")

type UserStore interface {
	Create(user domain.User) (domain.User, error)
	GetByID(id string) (domain.User, error)
	List() ([]domain.User, error)
	Update(user domain.User) (domain.User, error)
	Delete(id string) error
}

type GroupStore interface {
	Create(group domain.Group) (domain.Group, error)
	GetByID(id string) (domain.Group, error)
	List() ([]domain.Group, error)
	Update(group domain.Group) (domain.Group, error)
	Delete(id string) error
}

type FlowStore interface {
	Create(flow domain.Flow) (domain.Flow, error)
	GetByID(id string) (domain.Flow, error)
	List() ([]domain.Flow, error)
	Update(flow domain.Flow) (domain.Flow, error)
	Delete(id string) error
	DeleteExpired(now time.Time) (int, error)
}

type SessionStore interface {
	Create(session domain.Session) (domain.Session, error)
	GetByID(id string) (domain.Session, error)
	GetByRefreshToken(token string) (domain.Session, error)
	List() ([]domain.Session, error)
	Update(session domain.Session) (domain.Session, error)
	Delete(id string) error
	DeleteExpired(now time.Time) (int, error)
}
