package utils

import (
	"encoding/base64"
	"encoding/json"
	"mime/multipart"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm/utils"
)

type PaginationInfo struct {
	NextCursor *string `json:"next"`
	PrevCursor *string `json:"prev"`
}

type Cursor map[string]interface{}

const (
	maxPageSize     int = 150
	minPageSize     int = 1
	defaultPageSize int = 50
)

func CreateCursor(id uuid.UUID, createdAt time.Time, pointsNext bool) Cursor {
	return Cursor{
		"id":          id,
		"created_at":  createdAt,
		"points_next": pointsNext,
	}
}

func GeneratePager(next Cursor, prev Cursor, routeName string, ctx *fiber.Ctx) PaginationInfo {
	routeParams := fiber.Map{}
	route := ctx.Route()

	if route != nil {
		for _, param := range route.Params {
			routeParams[param] = ctx.Params(param)
		}
	}

	return PaginationInfo{
		NextCursor: CursorAbsoluteURL(encodeCursor(next), routeName, routeParams, ctx),
		PrevCursor: CursorAbsoluteURL(encodeCursor(prev), routeName, routeParams, ctx),
	}
}

func encodeCursor(cursor Cursor) *string {
	if len(cursor) == 0 {
		return nil
	}

	serializedCursor, err := json.Marshal(cursor)
	if err != nil {
		return nil
	}

	encodedCursor := base64.RawStdEncoding.EncodeToString(serializedCursor)

	return &encodedCursor
}

func DecodeCursor(cursor string) (Cursor, error) {
	decodedCursor, err := base64.RawStdEncoding.DecodeString(cursor)
	if err != nil {
		return nil, err
	}

	cur := Cursor{}

	if err := json.Unmarshal(decodedCursor, &cur); err != nil {
		return nil, err
	}

	return cur, nil
}

func GetPaginationSize(p string) int {
	perPage := os.Getenv("PAGINATE_PER_PAGE")

	if len(p) > 0 {
		perPage = p
	}

	limit, err := strconv.Atoi(perPage)
	if err != nil {
		limit = defaultPageSize
	}

	if limit < minPageSize {
		limit = minPageSize
	}

	if limit > maxPageSize {
		limit = maxPageSize
	}

	return limit
}

func HasValidMimeType(fh *multipart.FileHeader, mtl []string) bool {
	if len(mtl) < 1 {
		return false
	}

	mt := fh.Header.Get("Content-Type")

	return utils.Contains(mtl, mt)
}

func CursorAbsoluteURL(cur *string, n string, p fiber.Map, c *fiber.Ctx) *string {
	if cur == nil {
		return nil
	}

	// Base URL
	u, err := url.Parse(c.BaseURL())
	if err != nil {
		return cur
	}

	// Route URL
	route, err := c.GetRouteURL(n, p)
	if err != nil {
		return cur
	}

	// Parse route URL
	ru, err := url.ParseRequestURI(route)
	if err != nil {
		return cur
	}

	// Append route URL
	u.Path = ru.Path

	// Cursor query
	params := url.Values{}

	for key, value := range c.Queries() {
		params.Set(key, url.QueryEscape(value))
	}

	params.Set("cursor", url.QueryEscape(*cur))

	// Append cursor query
	u.RawQuery = params.Encode()

	// Absolute URL
	absUrl := u.Redacted()

	return &absUrl
}

func IsValidUuid(id uuid.UUID) bool {
	return id.Version() == 4 && id != uuid.Nil
}

func IsValidSearch(s string) bool {
	regex := regexp.MustCompile(`(?i)[\w]+`)

	return regex.MatchString(s)
}
