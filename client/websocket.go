package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
	"github.com/slipe-fun/bloom-kit/domain"
	"github.com/slipe-fun/bloom-kit/mappers"
	"github.com/slipe-fun/skid-v4/pkg/identity"
)

type WsEvent struct {
	Type string `json:"type"`
	Data []byte `json:"data"`
}

type ChatNewEvent struct {
	domain.Chat
	Type              string                    `json:"type"`
	ChatType          string                    `json:"chat_type"`
	UserID            string                    `json:"user_id"`
	Role              *string                   `json:"role,omitempty"`
	InvitedBy         *domain.User              `json:"invited_by,omitempty"`
	Handshake         *domain.Handshake         `json:"handshake,omitempty"`
	EncryptedGroupKey *domain.EncryptedGroupKey `json:"encrypted_group_key,omitempty"`
}

type MessageNewEvent struct {
	Type    string             `json:"type"`
	ID      int                `json:"id"`
	UserID  string             `json:"user_id"`
	ReplyTo *domain.RawMessage `json:"reply_to,omitempty"`
	*domain.RawMessageWithReply
}

func (m *MessageNewEvent) UnmarshalJSON(data []byte) error {
	var helper struct {
		Type    string             `json:"type"`
		ID      int                `json:"id"`
		UserID  string             `json:"user_id"`
		ReplyTo *domain.RawMessage `json:"reply_to,omitempty"`
	}

	if err := json.Unmarshal(data, &helper); err != nil {
		return err
	}

	var raw domain.RawMessageWithReply
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	m.Type = helper.Type
	m.ID = helper.ID
	m.UserID = helper.UserID
	m.ReplyTo = helper.ReplyTo
	m.RawMessageWithReply = &raw

	return nil
}

func (c *BloomClient) startWebSocket(ctx context.Context, wsURL string) {
	creds, err := c.getCredentials()
	if err != nil || creds.Token == "" {
		return
	}

	wsCtx, cancel := context.WithCancel(ctx)

	c.wsCancelMu.Lock()
	if c.wsCancel != nil {
		c.wsCancel()
	}
	c.wsCancel = cancel
	c.wsCancelMu.Unlock()

	go func() {
		defer cancel()

		backoff := time.Second

		for {
			select {
			case <-wsCtx.Done():
				return
			case <-time.After(backoff):
			}

			creds, err := c.getCredentials()
			if err != nil || creds.Token == "" {
				return
			}

			startedAt := time.Now()

			err = c.connectAndListen(wsCtx, fmt.Sprintf("%s?token=%s", wsURL, creds.Token))
			if err != nil && time.Since(startedAt) < 5*time.Second {
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}

			backoff = time.Second
		}
	}()
}

func (c *BloomClient) stopWebSocket() {
	c.wsCancelMu.Lock()
	if c.wsCancel != nil {
		c.wsCancel()
		c.wsCancel = nil
	}
	c.wsCancelMu.Unlock()

	c.wsMu.Lock()
	c.wsConnected = false
	c.wsMu.Unlock()
}

func (c *BloomClient) connectAndListen(ctx context.Context, url string) error {
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, url, nil)
	if err != nil {
		return fmt.Errorf("websocket dial error: %w", err)
	}
	defer conn.Close()

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if c.isReconnect() {
		c.notifyReconnect()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			_, message, err := conn.ReadMessage()
			if err != nil {
				return fmt.Errorf("websocket read error: %w", err)
			}

			var event WsEvent
			if err := json.Unmarshal(message, &event); err != nil {
				continue
			}

			switch event.Type {
			case "chat.new":
				var event ChatNewEvent
				if err := json.Unmarshal(message, &event); err != nil {
					continue
				}

				c.handleNewChatEvent(&event)
			case "message.new":
				var event MessageNewEvent
				if err := json.Unmarshal(message, &event); err != nil {
					fmt.Println(err)
					continue
				}

				c.handleNewMessageEvent(&event)
			}
		}
	}
}

func (c *BloomClient) isReconnect() bool {
	c.wsMu.Lock()
	defer c.wsMu.Unlock()

	if c.wsConnected {
		return true
	}

	c.wsConnected = true
	return false
}

func (c *BloomClient) notifyReconnect() {
	c.listenerMu.RLock()
	reconnectListener := c.reconnectListener
	c.listenerMu.RUnlock()

	if reconnectListener != nil {
		reconnectListener.OnReconnect()
	}
}

func (c *BloomClient) RegisterReconnectListener(listener ReconnectListener) {
	c.listenerMu.Lock()
	c.reconnectListener = listener
	c.listenerMu.Unlock()
}

func (c *BloomClient) UnregisterReconnectListener() {
	c.listenerMu.Lock()
	c.reconnectListener = nil
	c.listenerMu.Unlock()
}

func (c *BloomClient) handleNewChatEvent(chatEvent *ChatNewEvent) {
	if chatEvent == nil {
		return
	}

	chat := chatEvent.Chat

	if chat.Handshake == nil && chatEvent.Handshake != nil {
		chat.Handshake = chatEvent.Handshake
	}

	creds, err := c.loadCredentials()
	if err != nil {
		return
	}

	userIdentity, err := mappers.ConvertCredentialsToUser(creds)
	if err != nil {
		return
	}

	if existing, err := c.database.GetChat(chat.ID); err == nil && existing != nil && len(existing.ChatKey) > 0 {
		if recipient := getChatOtherMember(&chat, creds.UserID); recipient != nil {
			_ = c.database.SaveUser(recipient)
		}
		c.notifyChatsUpdated()
		return
	}

	chatType := chatEvent.ChatType
	if chatType == "" {
		chatType = chat.Type
	}

	switch chatType {
	case "private":
		recipient, err := getChatRecipient(&chat, creds.UserID)
		if err != nil {
			return
		}

		recipientIdentity, err := mappers.ConvertUserToIdentity(recipient)
		if err != nil {
			return
		}

		handshakePayload, err := mappers.DecodeHandshake(chat.Handshake)
		if err != nil {
			return
		}

		secretKeys, err := mappers.UnmapSecretKeys(creds.SecretKeys)
		if err != nil {
			return
		}
		defer secretKeys.Wipe()

		chatKey, syncKey, err := identity.FinalizeKeyExchange(handshakePayload, userIdentity, secretKeys, recipientIdentity, nil, true)
		if err != nil {
			chatKey, syncKey, err = identity.FinalizeKeyExchange(handshakePayload, recipientIdentity, nil, userIdentity, secretKeys, false)
			if err != nil {
				return
			}
		}

		err = c.database.SaveChat(chat, chatKey, syncKey)
		if err != nil {
			return
		}

		_ = c.database.SaveUser(recipient)
	case "group":
		if chat.Members != nil && len(*chat.Members) > 0 {
			_ = c.database.SaveUsers(*chat.Members)
		}
	}

	c.notifyChatsUpdated()
}

func (c *BloomClient) handleNewMessageEvent(messageEvent *MessageNewEvent) {
	if messageEvent == nil || messageEvent.RawMessageWithReply == nil {
		return
	}

	creds, err := c.getCredentials()
	if err != nil {
		return
	}

	chat, err := c.database.GetChat(messageEvent.ChatID)
	if err != nil {
		return
	}

	recipient, err := getChatRecipient(&domain.Chat{
		RawChat: chat.RawChat,
	}, creds.UserID)
	if err != nil {
		return
	}

	recipientIdentity, err := mappers.ConvertUserToIdentity(recipient)
	if err != nil {
		return
	}

	userIdentity, err := mappers.ConvertCredentialsToUser(creds)
	if err != nil {
		return
	}

	decryptedMessage, err := c.messageManager.DecryptMessage(messageEvent.RawMessageWithReply, chat.ChatKey, chat.SyncKey, userIdentity, recipientIdentity)
	if err != nil {
		return
	}
	if decryptedMessage == nil {
		return
	}

	var replyToMessage *domain.MessageWithDecryptedData
	if messageEvent.ReplyTo != nil {
		decryptedReply, err := c.messageManager.DecryptMessage(&domain.RawMessageWithReply{
			RawMessage: *messageEvent.ReplyTo,
		}, chat.ChatKey, chat.SyncKey, userIdentity, recipientIdentity)
		if err != nil {
			return
		}
		if decryptedReply == nil {
			return
		}

		replyToMessage = &domain.MessageWithDecryptedData{
			RawMessageWithReply: domain.RawMessageWithReply{
				RawMessage: *messageEvent.ReplyTo,
			},
			Message: *decryptedReply,
		}
	}

	msg := domain.Message{
		MessageWithDecryptedData: domain.MessageWithDecryptedData{
			RawMessageWithReply: *messageEvent.RawMessageWithReply,
			Message:             *decryptedMessage,
		},
		ReplyToMessage: replyToMessage,
	}

	err = c.database.SaveMessage(&msg)
	if err != nil {
		return
	}

	decryptedWithReply := mappers.MapDomainMessageToDecrypted(&msg)
	messageJSON, err := json.Marshal(decryptedWithReply)
	if err != nil {
		return
	}

	c.listenerMu.RLock()
	messagesListener := c.messagesListener
	c.listenerMu.RUnlock()

	if messagesListener != nil {
		messagesListener.OnNewMessage(messageJSON)
	}

	c.notifyChatsUpdated()
}
