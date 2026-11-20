package chat

import (
	"context"
	"fmt"

	"github.com/slipe-fun/bloom-kit/api"
	"github.com/slipe-fun/bloom-kit/domain"
)

func (c *ChatClient) GetChat(ctx context.Context, chatID int) (*domain.Chat, error) {
	return api.Send[struct{}, domain.Chat](
		ctx,
		c.client,
		"GET",
		fmt.Sprintf("/chat/%d", chatID),
		nil,
	)
}
