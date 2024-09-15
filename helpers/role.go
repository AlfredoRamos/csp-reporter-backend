package helpers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/models"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/redis/rueidis"
)

type userRole struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

type userRoleList []userRole

func (l userRoleList) Names() []string {
	names := []string{}

	for _, r := range l {
		names = append(names, r.Name)
	}

	return names
}

func (l userRoleList) IDs() []uuid.UUID {
	ids := []uuid.UUID{}

	for _, r := range l {
		ids = append(ids, r.ID)
	}

	return ids
}

func GetUserRoles(id uuid.UUID) (userRoleList, error) {
	if !utils.IsValidUuid(id) {
		return []userRole{}, errors.New("Invalid user ID.")
	}

	roles := []userRole{}

	cachedRoles, err := app.Cache().DoCache(context.Background(), app.Cache().B().Get().Key(fmt.Sprintf("roles:%s", id.String())).Cache(), 5*time.Minute).ToString()
	if err != nil && !errors.Is(err, rueidis.Nil) {
		slog.Warn(fmt.Sprintf("Could not get cached roles: %v", err))
	}

	if len(cachedRoles) > 0 {
		if err := json.Unmarshal([]byte(cachedRoles), &roles); err != nil {
			slog.Error(fmt.Sprintf("Could not decode cached roles: %v", err))
		}

		return roles, nil
	}

	limit := 10

	if err := app.DB().Model(&models.Role{}).
		Joins("INNER JOIN user_roles ur ON roles.id = ur.role_id").
		Joins("INNER JOIN users u ON ur.user_id = u.id").
		Where("ur.deleted_at IS NULL AND u.deleted_at IS NULL AND u.id = @user_id AND u.active = @active", sql.Named("user_id", id), sql.Named("active", true)).
		Limit(limit).Find(&roles).Error; err != nil {
		return []userRole{}, err
	}

	rawRoles, err := json.Marshal(roles)
	if err != nil {
		slog.Error(fmt.Sprintf("Could not serialize roles for cache: %v", err))
	}

	if err := app.Cache().Do(context.Background(), app.Cache().B().Set().Key(fmt.Sprintf("roles:%s", id.String())).Value(string(rawRoles)).Ex(24*time.Hour).Build()).Error(); err != nil {
		slog.Error(fmt.Sprintf("Could not save roles to cache: %v", err))
	}

	return roles, nil
}

func HasPermission(id uuid.UUID, p string, m string) bool {
	if !utils.IsValidUuid(id) {
		return false
	}

	r, err := GetUserRoles(id)
	if err != nil {
		slog.Error(fmt.Sprintf("User roles error: %v", err))
		r = []userRole{}
	}

	if len(r) < 1 {
		return false
	}

	ps := [][]interface{}{}

	for _, val := range r.Names() {
		ps = append(ps, []interface{}{val, p, m})
	}

	result, err := app.Auth().BatchEnforce(ps)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Enforce error: %v", err))
		return false
	}

	for _, val := range result {
		if val {
			return true
		}
	}

	return false
}
