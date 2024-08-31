package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Report struct {
	ID                 uuid.UUID      `gorm:"primaryKey;type:uuid;not null;unique;default:gen_random_uuid()" json:"id"`
	BlockedURI         string         `gorm:"type:text;not null" json:"blocked_uri"`
	Disposition        string         `gorm:"size:100;not null" json:"disposition"`
	DocumentURI        string         `gorm:"type:text;not null" json:"document_uri"`
	EffectiveDirective string         `gorm:"size:100;not null" json:"effective_directive"`
	OriginalPolicy     string         `gorm:"type:text;not null" json:"original_policy"`
	Referrer           *string        `gorm:"type:text" json:"referrer"`
	StatusCode         int            `gorm:"not null;check:status_code >= 0" json:"status_code"`
	ViolatedDirective  string         `gorm:"size:100;not null" json:"violated_directive"`
	ScriptSample       *string        `gorm:"size:50" json:"script_sample"`
	SourceFile         *string        `gorm:"type:text" json:"source_file"`
	LineNumber         *int64         `gorm:"check:line_number >= 0" json:"line_number"`
	ColumnNumber       *int64         `gorm:"check:column_number >= 0" json:"column_number"`
	CreatedAt          time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	UpdatedAt          time.Time      `gorm:"not null;default:clock_timestamp()" json:"-"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

func (r Report) GetID() uuid.UUID {
	return r.ID
}

func (r Report) GetCreatedAt() time.Time {
	return r.CreatedAt
}
