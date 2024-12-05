package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserActivation struct {
	ID           uuid.UUID      `gorm:"primaryKey;type:uuid;not null;unique;default:gen_random_uuid()" json:"id"`
	UserID       uuid.UUID      `gorm:"not null" json:"user_id"`
	User         User           `json:"user"`
	Approved     *bool          `gorm:"default:false" json:"approved"`
	Reason       *string        `gorm:"size:255" json:"reason"`
	ReviewedByID *uuid.UUID     `json:"reviewed_by_id"`
	ReviewedBy   *User          `gorm:"not null;foreignKey:ReviewedByID" json:"reviewed_by"`
	CreatedAt    time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	UpdatedAt    time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

func (ua UserActivation) GetID() uuid.UUID {
	return ua.ID
}

func (ua UserActivation) GetCreatedAt() time.Time {
	return ua.CreatedAt
}
