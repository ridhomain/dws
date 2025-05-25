package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
)

// TokenGenerator provides utilities for generating test tokens using AES-GCM encryption
type TokenGenerator struct {
	userAESKey  []byte
	adminAESKey []byte
	userGCM     cipher.AEAD
	adminGCM    cipher.AEAD
}

// NewTokenGenerator creates a new token generator with the provided AES keys
func NewTokenGenerator(userAESKeyHex, adminAESKeyHex string) (*TokenGenerator, error) {
	userKey, err := hex.DecodeString(userAESKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid user AES key: %w", err)
	}

	adminKey, err := hex.DecodeString(adminAESKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid admin AES key: %w", err)
	}

	userCipher, err := aes.NewCipher(userKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create user cipher: %w", err)
	}

	adminCipher, err := aes.NewCipher(adminKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create admin cipher: %w", err)
	}

	userGCM, err := cipher.NewGCM(userCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create user GCM: %w", err)
	}

	adminGCM, err := cipher.NewGCM(adminCipher)
	if err != nil {
		return nil, fmt.Errorf("failed to create admin GCM: %w", err)
	}

	return &TokenGenerator{
		userAESKey:  userKey,
		adminAESKey: adminKey,
		userGCM:     userGCM,
		adminGCM:    adminGCM,
	}, nil
}

// GenerateUserToken creates an encrypted user token with the specified parameters
func (tg *TokenGenerator) GenerateUserToken(companyID, agentID, userID string, expiresIn time.Duration) (string, error) {
	context := &domain.AuthenticatedUserContext{
		CompanyID: companyID,
		AgentID:   agentID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(expiresIn),
	}

	return tg.encryptUserContext(context)
}

// GenerateExpiredUserToken creates an expired user token for testing expiration handling
func (tg *TokenGenerator) GenerateExpiredUserToken(companyID, agentID, userID string) (string, error) {
	context := &domain.AuthenticatedUserContext{
		CompanyID: companyID,
		AgentID:   agentID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(-time.Hour), // Expired 1 hour ago
	}

	return tg.encryptUserContext(context)
}

// GenerateAdminToken creates an encrypted admin token with the specified parameters
func (tg *TokenGenerator) GenerateAdminToken(adminID, companyIDRestriction, subscribedCompanyID, subscribedAgentID string, expiresIn time.Duration) (string, error) {
	context := &domain.AdminUserContext{
		AdminID:              adminID,
		CompanyIDRestriction: companyIDRestriction,
		SubscribedCompanyID:  subscribedCompanyID,
		SubscribedAgentID:    subscribedAgentID,
		ExpiresAt:            time.Now().Add(expiresIn),
	}

	return tg.encryptAdminContext(context)
}

// GenerateExpiredAdminToken creates an expired admin token for testing expiration handling
func (tg *TokenGenerator) GenerateExpiredAdminToken(adminID, companyIDRestriction, subscribedCompanyID, subscribedAgentID string) (string, error) {
	context := &domain.AdminUserContext{
		AdminID:              adminID,
		CompanyIDRestriction: companyIDRestriction,
		SubscribedCompanyID:  subscribedCompanyID,
		SubscribedAgentID:    subscribedAgentID,
		ExpiresAt:            time.Now().Add(-time.Hour), // Expired 1 hour ago
	}

	return tg.encryptAdminContext(context)
}

// encryptUserContext encrypts a user context using AES-GCM
func (tg *TokenGenerator) encryptUserContext(context *domain.AuthenticatedUserContext) (string, error) {
	jsonData, err := json.Marshal(context)
	if err != nil {
		return "", fmt.Errorf("failed to marshal user context: %w", err)
	}

	nonce := make([]byte, tg.userGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := tg.userGCM.Seal(nonce, nonce, jsonData, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// encryptAdminContext encrypts an admin context using AES-GCM
func (tg *TokenGenerator) encryptAdminContext(context *domain.AdminUserContext) (string, error) {
	jsonData, err := json.Marshal(context)
	if err != nil {
		return "", fmt.Errorf("failed to marshal admin context: %w", err)
	}

	nonce := make([]byte, tg.adminGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := tg.adminGCM.Seal(nonce, nonce, jsonData, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// BatchTokenGenerator provides efficient bulk token generation for load testing
type BatchTokenGenerator struct {
	generator *TokenGenerator
}

// NewBatchTokenGenerator creates a new batch token generator
func NewBatchTokenGenerator(userAESKeyHex, adminAESKeyHex string) (*BatchTokenGenerator, error) {
	generator, err := NewTokenGenerator(userAESKeyHex, adminAESKeyHex)
	if err != nil {
		return nil, err
	}

	return &BatchTokenGenerator{
		generator: generator,
	}, nil
}

// GenerateUserTokens creates multiple user tokens for load testing
func (btg *BatchTokenGenerator) GenerateUserTokens(count int, companyID, agentID string, expiresIn time.Duration) ([]string, error) {
	tokens := make([]string, count)

	for i := 0; i < count; i++ {
		userID := fmt.Sprintf("user_%d", i)
		token, err := btg.generator.GenerateUserToken(companyID, agentID, userID, expiresIn)
		if err != nil {
			return nil, fmt.Errorf("failed to generate token %d: %w", i, err)
		}
		tokens[i] = token
	}

	return tokens, nil
}

// GenerateAdminTokens creates multiple admin tokens for load testing
func (btg *BatchTokenGenerator) GenerateAdminTokens(count int, companyIDRestriction, subscribedCompanyID, subscribedAgentID string, expiresIn time.Duration) ([]string, error) {
	tokens := make([]string, count)

	for i := 0; i < count; i++ {
		adminID := fmt.Sprintf("admin_%d", i)
		token, err := btg.generator.GenerateAdminToken(adminID, companyIDRestriction, subscribedCompanyID, subscribedAgentID, expiresIn)
		if err != nil {
			return nil, fmt.Errorf("failed to generate admin token %d: %w", i, err)
		}
		tokens[i] = token
	}

	return tokens, nil
}

// GenerateMixedTokens creates a mix of valid and expired tokens for testing
func (btg *BatchTokenGenerator) GenerateMixedTokens(validCount, expiredCount int, companyID, agentID string, expiresIn time.Duration) ([]string, error) {
	tokens := make([]string, validCount+expiredCount)

	// Generate valid tokens
	for i := 0; i < validCount; i++ {
		userID := fmt.Sprintf("valid_user_%d", i)
		token, err := btg.generator.GenerateUserToken(companyID, agentID, userID, expiresIn)
		if err != nil {
			return nil, fmt.Errorf("failed to generate valid token %d: %w", i, err)
		}
		tokens[i] = token
	}

	// Generate expired tokens
	for i := 0; i < expiredCount; i++ {
		userID := fmt.Sprintf("expired_user_%d", i)
		token, err := btg.generator.GenerateExpiredUserToken(companyID, agentID, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate expired token %d: %w", i, err)
		}
		tokens[validCount+i] = token
	}

	return tokens, nil
}

// TestTokenSet provides a comprehensive set of tokens for various test scenarios
type TestTokenSet struct {
	ValidUserTokens    []string
	ExpiredUserTokens  []string
	ValidAdminTokens   []string
	ExpiredAdminTokens []string
}

// GenerateTestTokenSet creates a comprehensive set of tokens for testing
func (btg *BatchTokenGenerator) GenerateTestTokenSet(companyID, agentID string) (*TestTokenSet, error) {
	const (
		validUserCount    = 100
		expiredUserCount  = 20
		validAdminCount   = 10
		expiredAdminCount = 5
		tokenTTL          = time.Hour
	)

	// Generate valid user tokens
	validUserTokens, err := btg.GenerateUserTokens(validUserCount, companyID, agentID, tokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate valid user tokens: %w", err)
	}

	// Generate expired user tokens
	expiredUserTokens := make([]string, expiredUserCount)
	for i := 0; i < expiredUserCount; i++ {
		userID := fmt.Sprintf("expired_user_%d", i)
		token, err := btg.generator.GenerateExpiredUserToken(companyID, agentID, userID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate expired user token %d: %w", i, err)
		}
		expiredUserTokens[i] = token
	}

	// Generate valid admin tokens
	validAdminTokens, err := btg.GenerateAdminTokens(validAdminCount, companyID, companyID, agentID, tokenTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to generate valid admin tokens: %w", err)
	}

	// Generate expired admin tokens
	expiredAdminTokens := make([]string, expiredAdminCount)
	for i := 0; i < expiredAdminCount; i++ {
		adminID := fmt.Sprintf("expired_admin_%d", i)
		token, err := btg.generator.GenerateExpiredAdminToken(adminID, companyID, companyID, agentID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate expired admin token %d: %w", i, err)
		}
		expiredAdminTokens[i] = token
	}

	return &TestTokenSet{
		ValidUserTokens:    validUserTokens,
		ExpiredUserTokens:  expiredUserTokens,
		ValidAdminTokens:   validAdminTokens,
		ExpiredAdminTokens: expiredAdminTokens,
	}, nil
}
