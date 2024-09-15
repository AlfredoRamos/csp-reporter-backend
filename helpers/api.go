package helpers

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"alfredoramos.mx/csp-reporter/app"
	"alfredoramos.mx/csp-reporter/utils"
	"github.com/getsentry/sentry-go"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

const (
	ASC  = "asc"
	DESC = "desc"
)

type PaginatedItem interface {
	GetID() uuid.UUID
	GetCreatedAt() time.Time
}

type PaginatedItemOpts struct {
	RouteName  string
	TableAlias string
}

func PaginateQuery[T PaginatedItem](items []T, query *gorm.DB, c *fiber.Ctx, opts PaginatedItemOpts) error {
	perPage := c.Query("per_page")
	sortOrder := c.Query("sort_order", "desc")
	cursor := c.Query("cursor")

	limit := utils.GetPaginationSize(perPage)

	isFirstPage := len(cursor) < 1
	pointsNext := false

	query, pointsNext, err := GetPaginationQuery(query, pointsNext, cursor, sortOrder, opts.TableAlias)
	if err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Error paginating results: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"Could not paginate results."},
		})
	}

	if err := query.Limit(limit + 1).Find(&items).Error; err != nil {
		slog.Error(fmt.Sprintf("Error getting paginated results: %v", err))
		return c.Status(fiber.StatusBadRequest).JSON(&fiber.Map{
			"error": []string{"Could not get results."},
		})
	}

	hasPagination := len(items) > int(limit)

	if hasPagination {
		items = items[:limit]
	}

	if !isFirstPage && !pointsNext {
		items = utils.Reverse(items)
	}

	pageInfo := CalculatePagination(isFirstPage, hasPagination, limit, items, pointsNext, opts.RouteName, c)

	return c.Status(fiber.StatusOK).JSON(&fiber.Map{
		"data": items,
		"next": pageInfo.NextCursor,
		"prev": pageInfo.PrevCursor,
	})
}

func GetPaginationQuery(query *gorm.DB, pointsNext bool, cursor string, sortOrder string, tableAlias string) (*gorm.DB, bool, error) {
	alias := ""

	if len(tableAlias) > 0 {
		alias = tableAlias + "."
	}

	if len(cursor) > 0 {
		decodedCursor, err := utils.DecodeCursor(cursor)
		if err != nil {
			sentry.CaptureException(err)
			slog.Error(fmt.Sprintf("Error decoding cursor: %v", err))
			return nil, pointsNext, err
		}

		pointsNext = decodedCursor["points_next"] == true
		operator, order := getPaginationOperator(pointsNext, sortOrder)
		whereStr := fmt.Sprintf("(%[1]screated_at %[2]s @created_at OR (%[1]screated_at = @created_at AND %[1]sid %[2]s @id))", alias, operator)
		query = query.Where(whereStr, sql.Named("created_at", decodedCursor["created_at"]), sql.Named("id", decodedCursor["id"]))

		if len(order) > 0 {
			sortOrder = order
		}
	}

	query = query.Order(fmt.Sprintf("%[1]screated_at %[2]s", alias, sortOrder))

	return query, pointsNext, nil
}

func getPaginationOperator(pointsNext bool, sortOrder string) (string, string) {
	if pointsNext && sortOrder == ASC {
		return ">", ""
	}

	if pointsNext && sortOrder == DESC {
		return "<", ""
	}

	if !pointsNext && sortOrder == ASC {
		return "<", DESC
	}

	if !pointsNext && sortOrder == DESC {
		return ">", ASC
	}

	return "", ""
}

func CalculatePagination[T PaginatedItem](isFirstPage bool, hasPagination bool, limit int, items []T, pointsNext bool, routeName string, ctx *fiber.Ctx) utils.PaginationInfo {
	nextCur := utils.Cursor{}
	prevCur := utils.Cursor{}

	if isFirstPage && hasPagination {
		nextCur = utils.CreateCursor(items[limit-1].GetID(), items[limit-1].GetCreatedAt(), true)
	}

	if !isFirstPage {
		if pointsNext {
			if hasPagination {
				nextCur = utils.CreateCursor(items[limit-1].GetID(), items[limit-1].GetCreatedAt(), true)
			}

			prevCur = utils.CreateCursor(items[0].GetID(), items[0].GetCreatedAt(), false)
		} else {
			nextCur = utils.CreateCursor(items[limit-1].GetID(), items[limit-1].GetCreatedAt(), true)

			if hasPagination {
				prevCur = utils.CreateCursor(items[0].GetID(), items[0].GetCreatedAt(), false)
			}
		}
	}

	pagination := utils.GeneratePager(nextCur, prevCur, routeName, ctx)

	if isFirstPage {
		pagination = utils.GeneratePager(nextCur, nil, routeName, ctx)
	}

	return pagination
}

func GetModelSchema(model any) *schema.Schema {
	stmt := &gorm.Statement{DB: app.DB()}
	if err := stmt.Parse(model); err != nil {
		sentry.CaptureException(err)
		slog.Error(fmt.Sprintf("Could not parse model: %v", err))
		return nil
	}

	return stmt.Schema
}
