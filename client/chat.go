package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/slipe-fun/bloom-kit/domain"
	"github.com/slipe-fun/bloom-kit/mappers"
	"github.com/slipe-fun/skid-v4/pkg/identity"
)

type CreateChatRequest struct {
	UserID            string
	MlKem768PublicKey string
	X448PublicKey     string
	Ed448PublicKey    string
}

type ChatResponse struct {
	domain.RawChat
	Me          []byte                            `json:"me"`
	Recipient   []byte                            `json:"recipient"`
	LastMessage *domain.DecryptedMessageWithReply `json:"last_message,omitempty"`
}

func (c *BloomClient) CreateChat(receiverUser *CreateChatRequest) ([]byte, error) {
	if _, err := c.getCredentials(); err != nil {
		return nil, err
	}

	createdChat, err := c.createChat(receiverUser)
	if err != nil {
		return nil, err
	}

	return json.Marshal(createdChat)
}

func (c *BloomClient) GetChats() ([]byte, error) {
	if _, err := c.getCredentials(); err != nil {
		return nil, err
	}

	chats, err := c.getChats()
	if err != nil {
		return nil, err
	}

	return json.Marshal(chats)
}

func (c *BloomClient) GetLocalChats() ([]byte, error) {
	if _, err := c.getCredentials(); err != nil {
		return nil, err
	}

	chats, err := c.getLocalChats()
	if err != nil {
		return nil, err
	}

	return json.Marshal(chats)
}

func (c *BloomClient) RegisterChatsListener(listener ChatsListener) {
	c.listenerMu.Lock()
	c.chatsListener = listener
	c.listenerMu.Unlock()

	c.notifyChatsUpdated()
}

func (c *BloomClient) UnregisterChatsListener() {
	c.listenerMu.Lock()
	c.chatsListener = nil
	c.listenerMu.Unlock()
}

func (c *BloomClient) StartChatsSync() {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()

	if c.syncCancel != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.syncCancel = cancel

	go func() {
		defer c.recoverBackground("chats-sync")

		c.syncRemoteChats()

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.syncRemoteChats()
			}
		}
	}()
}

func (c *BloomClient) StopChatsSync() {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()

	if c.syncCancel != nil {
		c.syncCancel()
		c.syncCancel = nil
	}
}

func getChatOtherMember(chat *domain.Chat, memberID string) *domain.User {
	if chat == nil || chat.Members == nil {
		return nil
	}

	for i := range *chat.Members {
		member := &(*chat.Members)[i]
		if member.ID == "" {
			continue
		}
		if member.ID != memberID {
			return member
		}
	}

	return nil
}

func getChatRecipient(chat *domain.Chat, memberID string) (*domain.User, error) {
	if chat == nil {
		return nil, domain.ErrInvalidChat
	}

	if memberID == "" {
		return nil, domain.ErrNotAuthenticated
	}

	if chat.Type != "" && chat.Type != "private" {
		return nil, fmt.Errorf("%w: %s", domain.ErrUnsupportedChatType, chat.Type)
	}

	if chat.Members != nil && len(*chat.Members) > 2 {
		return nil, fmt.Errorf("%w: chat has %d members", domain.ErrUnsupportedChatType, len(*chat.Members))
	}

	recipient := getChatOtherMember(chat, memberID)
	if recipient == nil {
		return nil, domain.ErrChatRecipientNotFound
	}

	return recipient, nil
}

func (c *BloomClient) createChat(receiverUser *CreateChatRequest) (*ChatResponse, error) {
	if receiverUser == nil {
		return nil, fmt.Errorf("%w: receiver request is nil", domain.ErrInvalidUserIdentity)
	}
	if receiverUser.UserID == "" {
		return nil, fmt.Errorf("%w: receiver user ID is empty", domain.ErrInvalidUserIdentity)
	}

	if _, err := c.getCredentials(); err != nil {
		return nil, err
	}

	creds, err := c.loadCredentials()
	if err != nil {
		return nil, err
	}

	sender, err := mappers.ConvertCredentialsToUser(creds)
	if err != nil {
		return nil, err
	}

	secretKeys, err := mappers.UnmapSecretKeys(creds.SecretKeys)
	if err != nil {
		return nil, err
	}
	defer secretKeys.Wipe()

	receiverPublicKeys, err := mappers.UnmapPublicKeys(&domain.PublicKeys{
		MlKem768: receiverUser.MlKem768PublicKey,
		X448:     receiverUser.X448PublicKey,
		Ed448:    receiverUser.Ed448PublicKey,
	})
	if err != nil {
		return nil, err
	}
	if len(receiverPublicKeys.MlKem768) == 0 || len(receiverPublicKeys.X448) == 0 || len(receiverPublicKeys.Ed448) == 0 {
		return nil, fmt.Errorf("%w: receiver has empty public keys", domain.ErrInvalidUserIdentity)
	}

	receiver := identity.User{
		ID: receiverUser.UserID,
		PublicKeys: identity.PublicKeys{
			MlKem768: receiverPublicKeys.MlKem768,
			X448:     receiverPublicKeys.X448,
			Ed448:    receiverPublicKeys.Ed448,
		},
	}

	createdChat, chatKey, syncKey, err := c.chatManager.Create(context.Background(), sender, &receiver, secretKeys)
	if err != nil {
		return nil, err
	}
	if createdChat == nil {
		return nil, domain.ErrInvalidChat
	}

	err = c.database.SaveChat(*createdChat, chatKey, syncKey)
	if err != nil {
		return nil, err
	}

	recipient, err := getChatRecipient(createdChat, creds.UserID)
	if err != nil {
		if !errors.Is(err, domain.ErrChatRecipientNotFound) {
			return nil, err
		}

		recipient = &domain.User{
			ID:             receiverUser.UserID,
			MlKemPublicKey: receiverUser.MlKem768PublicKey,
			EcdhPublicKey:  receiverUser.X448PublicKey,
			EdPublicKey:    receiverUser.Ed448PublicKey,
		}
	}

	recipientJSON, err := json.Marshal(recipient)
	if err != nil {
		return nil, err
	}

	response := ChatResponse{
		RawChat:   createdChat.RawChat,
		Me:        creds.UserJSON,
		Recipient: recipientJSON,
	}

	if createdChat.Members != nil && len(*createdChat.Members) > 0 {
		err = c.database.SaveUsers(*createdChat.Members)
	} else {
		err = c.database.SaveUser(recipient)
	}
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (c *BloomClient) getChats() (*[]ChatResponse, error) {
	if _, err := c.getCredentials(); err != nil {
		return nil, err
	}

	creds, err := c.loadCredentials()
	if err != nil {
		return nil, err
	}

	userIdentity, err := mappers.ConvertCredentialsToUser(creds)
	if err != nil {
		return nil, err
	}

	chats, err := c.chatManager.GetChats(context.Background())
	if err != nil {
		return nil, err
	}
	if chats == nil {
		return &[]ChatResponse{}, nil
	}

	localChats, err := c.database.GetChats()
	if err != nil {
		return nil, err
	}
	localChatsMap := make(map[int]domain.ChatWithKeys, len(localChats))
	for _, lc := range localChats {
		localChatsMap[lc.ID] = lc
	}

	chatsSlice := *chats
	var result []ChatResponse
	var ids []int
	var members []domain.User
	var messages []domain.Message

	chatsMap := make(map[int]*domain.Chat, len(chatsSlice))
	resultMap := make(map[int]int)

	for i := range chatsSlice {
		chat := &chatsSlice[i]
		chatsMap[chat.ID] = chat

		recipient, err := getChatRecipient(chat, creds.UserID)
		if err != nil {
			continue
		}

		recipientIdentity, err := mappers.ConvertUserToIdentity(recipient)
		if err != nil {
			continue
		}

		members = append(members, *recipient)
		ids = append(ids, chat.ID)

		recipientJSON, err := json.Marshal(recipient)
		if err != nil {
			continue
		}

		newChatObject := ChatResponse{
			RawChat:   chat.RawChat,
			Me:        creds.UserJSON,
			Recipient: recipientJSON,
		}

		if lc, exists := localChatsMap[chat.ID]; exists {
			if chat.EncryptedLastMessage != nil {
				if lc.LastMessage != nil && lc.LastMessage.ID == chat.EncryptedLastMessage.ID {
					mapped := mappers.MapDomainMessageToDecrypted(lc.LastMessage)
					newChatObject.LastMessage = &mapped
				} else {
					decryptedLastMessage, err := c.messageManager.DecryptMessage(chat.EncryptedLastMessage, lc.ChatKey, lc.SyncKey, userIdentity, recipientIdentity)
					if err == nil {
						msg := domain.Message{
							MessageWithDecryptedData: domain.MessageWithDecryptedData{
								RawMessageWithReply: *chat.EncryptedLastMessage,
								Message:             *decryptedLastMessage,
							},
						}
						messages = append(messages, msg)
						mapped := mappers.MapDomainMessageToDecrypted(&msg)
						newChatObject.LastMessage = &mapped
					} else if lc.LastMessage != nil {
						mapped := mappers.MapDomainMessageToDecrypted(lc.LastMessage)
						newChatObject.LastMessage = &mapped
					}
				}
			} else if lc.LastMessage != nil {
				mapped := mappers.MapDomainMessageToDecrypted(lc.LastMessage)
				newChatObject.LastMessage = &mapped
			}
		}

		result = append(result, newChatObject)
		resultMap[chat.ID] = len(result) - 1
	}

	missing, err := c.database.GetMissingChatIDs(ids)
	if err != nil {
		return nil, err
	}

	secretKeys, err := mappers.UnmapSecretKeys(creds.SecretKeys)
	if err != nil {
		return nil, err
	}
	defer secretKeys.Wipe()

	var missingChats []domain.ChatWithKeys
	for _, id := range missing {
		chat, exists := chatsMap[id]
		if !exists {
			continue
		}

		recipient, err := getChatRecipient(chat, creds.UserID)
		if err != nil {
			continue
		}

		recipientIdentity, err := mappers.ConvertUserToIdentity(recipient)
		if err != nil {
			continue
		}

		handshakePayload, err := mappers.DecodeHandshake(chat.Handshake)
		if err != nil {
			continue
		}

		chatKey, syncKey, err := c.chatManager.FinalizeHandshake(handshakePayload, userIdentity, secretKeys, recipientIdentity)
		if err != nil {
			continue
		}

		if chat.EncryptedLastMessage != nil {
			decLastMessage, err := c.messageManager.DecryptMessage(chat.EncryptedLastMessage, chatKey, syncKey, userIdentity, recipientIdentity)
			if err == nil {
				msg := domain.Message{
					MessageWithDecryptedData: domain.MessageWithDecryptedData{
						RawMessageWithReply: *chat.EncryptedLastMessage,
						Message:             *decLastMessage,
					},
				}
				messages = append(messages, msg)

				if idx, found := resultMap[id]; found {
					mapped := mappers.MapDomainMessageToDecrypted(&msg)
					result[idx].LastMessage = &mapped
				}
			}
		}

		newChat := domain.ChatWithKeys{
			RawChat: chat.RawChat,
			ChatKey: chatKey,
			SyncKey: syncKey,
		}

		missingChats = append(missingChats, newChat)
	}

	if len(missingChats) > 0 {
		err = c.database.SaveChats(missingChats)
		if err != nil {
			return nil, err
		}
	}

	if len(members) > 0 {
		err = c.database.SaveUsers(members)
		if err != nil {
			return nil, err
		}
	}

	if len(messages) > 0 {
		err = c.database.SaveMessages(messages)
		if err != nil {
			return nil, err
		}
	}

	return &result, nil
}

func (c *BloomClient) getLocalChats() ([]ChatResponse, error) {
	creds, err := c.getCredentials()
	if err != nil {
		return nil, err
	}

	chats, err := c.database.GetChats()
	if err != nil {
		return nil, err
	}

	sort.SliceStable(chats, func(i, j int) bool {
		leftDate := chats[i].CreatedAt
		if chats[i].LastMessage != nil {
			leftDate = chats[i].LastMessage.CreatedAt
		}

		rightDate := chats[j].CreatedAt
		if chats[j].LastMessage != nil {
			rightDate = chats[j].LastMessage.CreatedAt
		}

		return leftDate.After(rightDate)
	})

	result := make([]ChatResponse, 0, len(chats))
	for i := range chats {
		chat := &chats[i]

		recipient, err := getChatRecipient(&domain.Chat{
			RawChat: chat.RawChat,
		}, creds.UserID)
		if err != nil {
			continue
		}

		recipientJSON, err := json.Marshal(recipient)
		if err != nil {
			continue
		}

		var lastMessage *domain.DecryptedMessageWithReply
		if chat.LastMessage != nil {
			mapped := mappers.MapDomainMessageToDecrypted(chat.LastMessage)
			lastMessage = &mapped
		}

		newChatObject := ChatResponse{
			RawChat:     chat.RawChat,
			Me:          creds.UserJSON,
			Recipient:   recipientJSON,
			LastMessage: lastMessage,
		}

		result = append(result, newChatObject)
	}

	return result, nil
}

func (c *BloomClient) notifyChatsUpdated() {
	c.listenerMu.Lock()
	listener := c.chatsListener
	c.listenerMu.Unlock()

	if listener == nil {
		return
	}

	localChatsBytes, err := c.GetLocalChats()
	if err != nil {
		fmt.Println("error", err)
		return
	}

	listener.OnChatsUpdated(localChatsBytes)
}

func (c *BloomClient) syncRemoteChats() {
	_, err := c.getChats()
	if err != nil {
		fmt.Println("error", err)
		return
	}

	c.notifyChatsUpdated()
}
