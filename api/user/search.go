package user

import (
	"context"
	"net/url"

	"github.com/slipe-fun/bloom-kit/api"
	"github.com/slipe-fun/bloom-kit/domain"
)

func (u *UserClient) Search(ctx context.Context, query string) (*[]domain.User, error) {
	values := url.Values{}
	values.Set("q", query)

	return api.Send[struct{}, []domain.User](
		ctx,
		u.client,
		"GET",
		"/user/search?"+values.Encode(),
		nil,
	)
}
