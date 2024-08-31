package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Site struct {
	ID        uuid.UUID      `gorm:"primaryKey;type:uuid;not null;unique;default:gen_random_uuid()" json:"id"`
	Title     *string        `gorm:"size:255" json:"title"`
	Domain    string         `gorm:"not null;size:255;unique" json:"domain"`
	CreatedAt time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	UpdatedAt time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}
