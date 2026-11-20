package user

import (
	"context"
	"net/url"
	"strings"

	"github.com/slipe-fun/bloom-kit/api"
	"github.com/slipe-fun/bloom-kit/domain"
)

func (u *UserClient) GetByIDs(ctx context.Context, ids []string) (*[]domain.User, error) {
	values := url.Values{}
	values.Set("ids", strings.Join(ids, ","))

	return api.Send[struct{}, []domain.User](
		ctx,
		u.client,
		"GET",
		"/users?"+values.Encode(),
		nil,
	)
}
