package rediskeys

import (
	"fmt"

	"gitlab.com/timkado/api/daisi-ws-service/pkg/crypto" // Path based on previous correction
)

// TokenCacheKey generates the Redis key for caching a validated company token.
// It takes the original raw token string, hashes it, and then formats the key.
func TokenCacheKey(rawToken string) string {
	hashedToken := crypto.Sha256Hex(rawToken)
	return fmt.Sprintf("token_cache:%s", hashedToken)
}

// SessionKey generates the Redis key for a user session.
func SessionKey(company, agent, user string) string {
	return fmt.Sprintf("session:%s:%s:%s", company, agent, user)
}

// RouteKeyChats generates the Redis key for chat routes.
func RouteKeyChats(company, agent string) string {
	return fmt.Sprintf("route:%s:%s:chats", company, agent)
}

// RouteKeyMessages generates the Redis key for message routes.
func RouteKeyMessages(company, agent, chatID string) string {
	return fmt.Sprintf("route:%s:%s:messages:%s", company, agent, chatID)
}

// SessionKillChannelKey generates the Redis key for the session kill pub/sub channel.
func SessionKillChannelKey(company, agent, user string) string {
	return fmt.Sprintf("session_kill:%s:%s:%s", company, agent, user)
}
