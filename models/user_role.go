package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRole struct {
	ID          uuid.UUID      `gorm:"primaryKey;type:uuid;not null;unique;default:gen_random_uuid()" json:"id"`
	UserID      uuid.UUID      `gorm:"not null" json:"user_id"`
	User        User           `json:"user"`
	RoleID      uuid.UUID      `gorm:"not null" json:"role_id"`
	Role        Role           `json:"role"`
	CreatedAt   time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	UpdatedAt   time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedByID uuid.UUID      `gorm:"not null" json:"-"`
	CreatedBy   User           `gorm:"not null;foreignKey:CreatedByID" json:"-"`
	UpdatedByID uuid.UUID      `gorm:"not null" json:"-"`
	UpdatedBy   User           `gorm:"not null;foreignKey:UpdatedByID" json:"-"`
	DeletedByID *uuid.UUID     `json:"-"`
	DeletedBy   *User          `gorm:"foreignKey:DeletedByID" json:"-"`
}
