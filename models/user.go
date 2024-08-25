package models

import (
	"strings"
	"time"

	"alfredoramos.mx/csp-reporter/utils"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID                 uuid.UUID      `gorm:"primaryKey;type:uuid;not null;unique;default:gen_random_uuid()" json:"id"`
	FirstName          *string        `gorm:"size:100" json:"first_name"`
	LastName           *string        `gorm:"size:100" json:"last_name"`
	Email              string         `gorm:"size:100;not null;unique" json:"email"`
	Password           string         `gorm:"size:255;not null" json:"-"`
	Active             *bool          `gorm:"not null;default:false" json:"active"`
	LastLogin          *time.Time     `json:"-"`
	LastPasswordChange *time.Time     `json:"-"`
	MustChangePassword *bool          `gorm:"default:false" json:"-"`
	CreatedAt          time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	UpdatedAt          time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

func (u *User) BeforeDelete(tx *gorm.DB) error {
	password, err := utils.RandomPassword(35)
	if err != nil {
		return err
	}

	active := false
	now := time.Now().In(utils.DefaultLocation())
	changePass := true

	return tx.Model(&u).Where(&User{ID: u.ID}).Updates(&User{
		Password:           utils.HashPassword(password),
		Active:             &active,
		LastPasswordChange: &now,
		MustChangePassword: &changePass,
	}).Error
}

func (u User) GetID() uuid.UUID {
	return u.ID
}

func (u User) GetCreatedAt() time.Time {
	return u.CreatedAt
}

func (u User) GetFullName() string {
	n := ""

	if u.FirstName != nil && len(*u.FirstName) > 0 {
		n += strings.TrimSpace(*u.FirstName)
	}

	if u.LastName != nil && len(*u.LastName) > 0 {
		n += " " + strings.TrimSpace(*u.LastName)
	}

	n = strings.TrimSpace(n)

	return n
}
