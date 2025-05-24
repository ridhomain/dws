package http

import (
	"encoding/json"
	"net/http"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/internal/adapters/config"
	"gitlab.com/timkado/api/daisi-ws-service/internal/domain"
	"gitlab.com/timkado/api/daisi-ws-service/pkg/crypto"
)

// GenerateTokenRequest is the expected payload for the /generate-token endpoint.
type GenerateTokenRequest struct {
	CompanyID        string `json:"company_id"`
	AgentID          string `json:"agent_id"`
	UserID           string `json:"user_id"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

// GenerateTokenResponse is the response from the /generate-token endpoint.
type GenerateTokenResponse struct {
	Token string `json:"token"`
}

// GenerateTokenHandler creates and returns an encrypted company token.
func GenerateTokenHandler(cfgProvider config.Provider, logger domain.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			logger.Warn(r.Context(), "Invalid method for /generate-token", "method", r.Method)
			domain.NewErrorResponse(domain.ErrMethodNotAllowed, "Method not allowed", "Only POST method is allowed.").WriteJSON(w, http.StatusMethodNotAllowed)
			return
		}

		var reqPayload GenerateTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&reqPayload); err != nil {
			logger.Warn(r.Context(), "Failed to decode /generate-token payload", "error", err.Error())
			domain.NewErrorResponse(domain.ErrBadRequest, "Invalid request payload", err.Error()).WriteJSON(w, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		// Validate payload
		if reqPayload.CompanyID == "" || reqPayload.AgentID == "" || reqPayload.UserID == "" || reqPayload.ExpiresInSeconds <= 0 {
			logger.Warn(r.Context(), "Invalid payload for /generate-token", "payload", reqPayload)
			domain.NewErrorResponse(domain.ErrBadRequest, "Invalid payload", "company_id, agent_id, user_id, and positive expires_in_seconds are required.").WriteJSON(w, http.StatusBadRequest)
			return
		}

		appCfg := cfgProvider.Get()
		if appCfg.Auth.TokenAESKey == "" {
			logger.Error(r.Context(), "TokenAESKey not configured for /generate-token")
			domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "Token encryption key not configured.").WriteJSON(w, http.StatusInternalServerError)
			return
		}

		tokenAuthContext := domain.AuthenticatedUserContext{
			CompanyID: reqPayload.CompanyID,
			AgentID:   reqPayload.AgentID,
			UserID:    reqPayload.UserID,
			ExpiresAt: time.Now().Add(time.Duration(reqPayload.ExpiresInSeconds) * time.Second),
		}

		plaintextTokenPayload, err := json.Marshal(tokenAuthContext)
		if err != nil {
			logger.Error(r.Context(), "Failed to marshal token context for /generate-token", "error", err.Error())
			domain.NewErrorResponse(domain.ErrInternal, "Failed to create token", "Internal error during token generation.").WriteJSON(w, http.StatusInternalServerError)
			return
		}

		encryptedToken, err := crypto.EncryptAESGCM(appCfg.Auth.TokenAESKey, plaintextTokenPayload)
		if err != nil {
			logger.Error(r.Context(), "Failed to encrypt token for /generate-token", "error", err.Error())
			domain.NewErrorResponse(domain.ErrInternal, "Failed to create token", "Internal error during token encryption.").WriteJSON(w, http.StatusInternalServerError)
			return
		}

		resp := GenerateTokenResponse{Token: encryptedToken}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error(r.Context(), "Failed to encode /generate-token response", "error", err.Error())
			// Hard to do much if response writing itself fails
		}
	}
}

// GenerateAdminTokenRequest defines the payload for creating admin tokens.
type GenerateAdminTokenRequest struct {
	AdminID              string `json:"admin_id"`
	ExpiresInSeconds     int    `json:"expires_in_seconds"`
	SubscribedCompanyID  string `json:"subscribed_company_id,omitempty"`  // For NATS subscription scoping. Empty means wildcard '*'.
	SubscribedAgentID    string `json:"subscribed_agent_id,omitempty"`    // For NATS subscription scoping. Empty means wildcard '*'.
	CompanyIDRestriction string `json:"company_id_restriction,omitempty"` // For data access restriction, if different from NATS scope.
}

// GenerateAdminTokenResponse defines the response for admin token generation.
type GenerateAdminTokenResponse struct {
	Token string `json:"token"`
}

// GenerateAdminTokenHandler creates admin tokens with specified scopes.
func GenerateAdminTokenHandler(cfgProvider config.Provider, logger domain.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			logger.Warn(r.Context(), "Invalid method for /admin/generate-token", "method", r.Method)
			domain.NewErrorResponse(domain.ErrMethodNotAllowed, "Method not allowed", "Only POST method is allowed.").WriteJSON(w, http.StatusMethodNotAllowed)
			return
		}

		var reqPayload GenerateAdminTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&reqPayload); err != nil {
			logger.Warn(r.Context(), "Failed to decode /admin/generate-token payload", "error", err.Error())
			domain.NewErrorResponse(domain.ErrBadRequest, "Invalid request payload", err.Error()).WriteJSON(w, http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if reqPayload.AdminID == "" || reqPayload.ExpiresInSeconds <= 0 {
			logger.Warn(r.Context(), "Invalid payload for /admin/generate-token", "payload", reqPayload)
			domain.NewErrorResponse(domain.ErrBadRequest, "Invalid payload", "admin_id and positive expires_in_seconds are required.").WriteJSON(w, http.StatusBadRequest)
			return
		}

		appAuthCfg := cfgProvider.Get().Auth
		if appAuthCfg.AdminTokenAESKey == "" {
			logger.Error(r.Context(), "AdminTokenAESKey not configured for /admin/generate-token")
			domain.NewErrorResponse(domain.ErrInternal, "Server configuration error", "Admin token encryption key not configured.").WriteJSON(w, http.StatusInternalServerError)
			return
		}

		adminTokenContext := domain.AdminUserContext{
			AdminID:              reqPayload.AdminID,
			ExpiresAt:            time.Now().Add(time.Duration(reqPayload.ExpiresInSeconds) * time.Second),
			SubscribedCompanyID:  reqPayload.SubscribedCompanyID, // Will be used by AdminHandler, defaults to '*' if empty there
			SubscribedAgentID:    reqPayload.SubscribedAgentID,   // Will be used by AdminHandler, defaults to '*' if empty there
			CompanyIDRestriction: reqPayload.CompanyIDRestriction,
		}

		plaintextTokenPayload, err := json.Marshal(adminTokenContext)
		if err != nil {
			logger.Error(r.Context(), "Failed to marshal admin token context for /admin/generate-token", "error", err.Error())
			domain.NewErrorResponse(domain.ErrInternal, "Failed to create admin token", "Internal error during token generation.").WriteJSON(w, http.StatusInternalServerError)
			return
		}

		encryptedToken, err := crypto.EncryptAESGCM(appAuthCfg.AdminTokenAESKey, plaintextTokenPayload)
		if err != nil {
			logger.Error(r.Context(), "Failed to encrypt admin token for /admin/generate-token", "error", err.Error())
			domain.NewErrorResponse(domain.ErrInternal, "Failed to create admin token", "Internal error during token encryption.").WriteJSON(w, http.StatusInternalServerError)
			return
		}

		resp := GenerateAdminTokenResponse{Token: encryptedToken}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			logger.Error(r.Context(), "Failed to encode /admin/generate-token response", "error", err.Error())
		}
	}
}
