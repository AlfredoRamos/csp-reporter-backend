package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Role struct {
	ID        uuid.UUID      `gorm:"primaryKey;type:uuid;not null;unique;default:gen_random_uuid()" json:"id"`
	Title     string         `gorm:"size:50;not null" json:"title"`
	Name      string         `gorm:"size:50;not null;unique" json:"name"`
	CreatedAt time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	UpdatedAt time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (h Role) GetID() uuid.UUID {
	return h.ID
}

func (h Role) GetCreatedAt() time.Time {
	return h.CreatedAt
}
