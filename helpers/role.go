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
	"github.com/google/uuid"
	"github.com/redis/rueidis"
)

// TODO: Store both UUID and role name
func GetUserRoles(id uuid.UUID) ([]uuid.UUID, error) {
	if !utils.IsValidUuid(id) {
		return []uuid.UUID{}, errors.New("Invalid user ID.")
	}

	roleIDs := []uuid.UUID{}

	// Try to load from cache
	cachedRoles, err := app.Cache().DoCache(context.Background(), app.Cache().B().Get().Key(fmt.Sprintf("role:ids:%s", id.String())).Cache(), 5*time.Minute).ToString()
	if err != nil && !errors.Is(err, rueidis.Nil) {
		slog.Warn(fmt.Sprintf("Could not get cached roles: %v", err))
	}

	if len(cachedRoles) > 0 {
		if err := json.Unmarshal([]byte(cachedRoles), &roleIDs); err != nil {
			slog.Error(fmt.Sprintf("Could not decode cached roles: %v", err))
		}

		return roleIDs, nil
	}

	if err := app.DB().
		Where("active = @active", sql.Named("active", true)).
		First(&models.User{ID: id}).Error; err != nil {
		return []uuid.UUID{}, errors.New("The requested user does not exist.")
	}

	limit := 10

	if err := app.DB().Model(&models.UserRole{}).
		Where(&models.UserRole{UserID: id}).
		Limit(limit).Pluck("RoleID", &roleIDs).Error; err != nil || len(roleIDs) < 1 {
		return []uuid.UUID{}, errors.New("The user does not have roles assigned.")
	}

	// Save roles to cache
	rawRoles, err := json.Marshal(roleIDs)
	if err != nil {
		slog.Error(fmt.Sprintf("Could not serialize roles for cache: %v", err))
	}

	if err := app.Cache().Do(context.Background(), app.Cache().B().Set().Key(fmt.Sprintf("role:ids:%s", id.String())).Value(string(rawRoles)).Ex(24*time.Hour).Build()).Error(); err != nil {
		slog.Error(fmt.Sprintf("Could not save roles to cache: %v", err))
	}

	return roleIDs, nil
}

// TODO: Remove
func GetUserRoleNames(id uuid.UUID) ([]string, error) {
	if !utils.IsValidUuid(id) {
		return []string{}, errors.New("Invalid user ID.")
	}

	roles := []string{}

	// Try to load from cache
	cachedRoles, err := app.Cache().DoCache(context.Background(), app.Cache().B().Get().Key(fmt.Sprintf("role:names:%s", id.String())).Cache(), 5*time.Minute).ToString()
	if err != nil && !errors.Is(err, rueidis.Nil) {
		slog.Warn(fmt.Sprintf("Could not get cached roles: %v", err))
	}

	if len(cachedRoles) > 0 {
		if err := json.Unmarshal([]byte(cachedRoles), &roles); err != nil {
			slog.Error(fmt.Sprintf("Could not decode cached roles: %v", err))
		}

		return roles, nil
	}

	if err := app.DB().
		Where("active = @active", sql.Named("active", true)).
		First(&models.User{ID: id}).Error; err != nil {
		return []string{}, errors.New("The requested user does not exist.")
	}

	limit := 10

	roleIDs := []uuid.UUID{}
	if err := app.DB().Model(&models.UserRole{}).
		Where(&models.UserRole{UserID: id}).
		Preload("Role").
		Limit(limit).Pluck("RoleID", &roleIDs).Error; err != nil || len(roleIDs) < 1 {
		return []string{}, errors.New("Could not get user roles.")
	}

	if err := app.DB().Model(&models.Role{}).
		Where("id IN @role_list", sql.Named("role_list", roleIDs)).
		Limit(limit).Pluck("Name", &roles).Error; err != nil || len(roles) < 1 {
		return []string{}, errors.New("Could not get user role list.")
	}

	// Save roles to cache
	rawRoles, err := json.Marshal(roles)
	if err != nil {
		slog.Error(fmt.Sprintf("Could not serialize roles for cache: %v", err))
	}

	if err := app.Cache().Do(context.Background(), app.Cache().B().Set().Key(fmt.Sprintf("role:names:%s", id.String())).Value(string(rawRoles)).Ex(24*time.Hour).Build()).Error(); err != nil {
		slog.Error(fmt.Sprintf("Could not save roles to cache: %v", err))
	}

	return roles, nil
}

func HasPermission(id uuid.UUID, p string, m string) bool {
	if !utils.IsValidUuid(id) {
		return false
	}

	r, err := GetUserRoleNames(id)
	if err != nil {
		slog.Error(fmt.Sprintf("User roles error: %v", err))
		r = []string{}
	}

	if len(r) < 1 {
		return false
	}

	ps := [][]interface{}{}

	for _, val := range r {
		ps = append(ps, []interface{}{val, p, m})
	}

	result, err := app.Auth().BatchEnforce(ps)
	if err != nil {
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
