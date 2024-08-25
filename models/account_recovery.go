package models

import (
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AccountRecovery struct {
	ID        uuid.UUID      `gorm:"primaryKey;type:uuid;not null;unique;default:gen_random_uuid()" json:"id"`
	Hash      string         `gorm:"not null;unique" json:"hash"`
	UserID    uuid.UUID      `gorm:"not null" json:"user_id"`
	User      User           `json:"user"`
	ExpiresAt time.Time      `gorm:"not null" json:"expires_at"`
	CreatedAt time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	UpdatedAt time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (ar AccountRecovery) URL() string {
	return fmt.Sprintf("%s/auth/recover?hash=%s", os.Getenv("APP_DOMAIN"), ar.Hash)
}
