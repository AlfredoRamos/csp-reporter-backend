package helpers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/models"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/rueidis"
)

func UserExists(id uuid.UUID, email string) bool {
	if !utils.IsValidUuid(id) || !utils.IsValidEmail(email) {
		return false
	}

	cachedUser, err := app.Cache().DoCache(context.Background(), app.Cache().B().Get().Key(fmt.Sprintf("user:%s", id.String())).Cache(), 5*time.Minute).ToString()
	if err != nil && !errors.Is(err, rueidis.Nil) {
		slog.Warn(fmt.Sprintf("Could not get cached user: %v", err))
	}

	exists := len(cachedUser) > 0 && cachedUser == email

	if exists {
		return true
	}

	user := &models.User{}
	if err := app.DB().Where(&models.User{ID: id, Email: email}).First(&user).Error; err != nil {
		return false
	}

	exists = utils.IsValidUuid(user.ID)

	if exists {
		if err := app.Cache().Do(context.Background(), app.Cache().B().Set().Key(fmt.Sprintf("user:%s", id.String())).Value(user.Email).Ex(time.Hour).Build()).Error(); err != nil {
			slog.Error(fmt.Sprintf("Could not save user to cache: %v", err))
		}
	}

	return exists
}

func GetUserID(c *fiber.Ctx) uuid.UUID {
	jwe := c.Locals(utils.TokenContextKey()).(string)
	claims, err := utils.ParseJWEClaims(jwe)
	if err != nil {
		panic(err)
	}

	return uuid.MustParse(claims.User.ID.String())
}
