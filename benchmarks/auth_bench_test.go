package benchmarks

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gitlab.com/timkado/api/daisi-ws-service/benchmarks/mocks"
	"gitlab.com/timkado/api/daisi-ws-service/benchmarks/utils"
	"gitlab.com/timkado/api/daisi-ws-service/internal/application"
)

var (
	testCompanyID = "test-company-123"
	testAgentID   = "test-agent-456"
	testUserID    = "test-user-789"
	testAdminID   = "test-admin-123"
)

// setupAuthBenchmark creates a test environment for authentication benchmarks
func setupAuthBenchmark(b *testing.B) (*application.AuthService, *utils.TokenGenerator, *mocks.MockTokenCacheStore, *mocks.MockAdminTokenCacheStore) {
	b.Helper()

	// Create mock config provider
	mockConfig := mocks.NewMockConfigProvider()
	cfg := mockConfig.Get()

	// Create mock dependencies
	userCache := mocks.NewMockTokenCacheStore()
	adminCache := mocks.NewMockAdminTokenCacheStore()

	// Create mock logger
	logger := mocks.NewMockLogger()

	// Create token generator
	tokenGen, err := utils.NewTokenGenerator(cfg.Auth.TokenAESKey, cfg.Auth.AdminTokenAESKey)
	if err != nil {
		b.Fatalf("Failed to create token generator: %v", err)
	}

	// Create auth service with mock dependencies
	authService := application.NewAuthService(
		logger,
		mockConfig,
		userCache,
		adminCache,
	)

	return authService, tokenGen, userCache, adminCache
}

// BenchmarkUserTokenValidation tests user token validation performance
func BenchmarkUserTokenValidation(b *testing.B) {
	authService, tokenGen, userCache, _ := setupAuthBenchmark(b)

	// Generate test tokens
	validToken, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, testUserID, time.Hour)
	if err != nil {
		b.Fatalf("Failed to generate valid token: %v", err)
	}

	expiredToken, err := tokenGen.GenerateExpiredUserToken(testCompanyID, testAgentID, testUserID)
	if err != nil {
		b.Fatalf("Failed to generate expired token: %v", err)
	}

	ctx := context.Background()

	b.Run("ValidToken", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := authService.ProcessToken(ctx, validToken)
			if err != nil {
				b.Errorf("Token validation failed: %v", err)
			}
		}
	})

	b.Run("ExpiredToken", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := authService.ProcessToken(ctx, expiredToken)
			if err == nil {
				b.Error("Expected expired token to fail validation")
			}
		}
	})

	b.Run("CacheHitScenario", func(b *testing.B) {
		// Pre-populate cache
		userCtx, _ := authService.ProcessToken(ctx, validToken)
		if userCtx != nil {
			userCache.Set(ctx, validToken, userCtx, time.Hour)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := authService.ProcessToken(ctx, validToken)
			if err != nil {
				b.Errorf("Cached token validation failed: %v", err)
			}
		}

		hitRatio := userCache.GetHitRatio()
		b.Logf("Cache hit ratio: %.2f%%", hitRatio*100)
	})

	b.Run("CacheMissScenario", func(b *testing.B) {
		// Clear cache to force misses
		userCache.Reset()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := authService.ProcessToken(ctx, validToken)
			if err != nil {
				b.Errorf("Token validation failed: %v", err)
			}
		}

		hitRatio := userCache.GetHitRatio()
		b.Logf("Cache hit ratio: %.2f%%", hitRatio*100)
	})
}

// BenchmarkAdminTokenValidation tests admin token validation performance
func BenchmarkAdminTokenValidation(b *testing.B) {
	authService, tokenGen, _, adminCache := setupAuthBenchmark(b)

	// Generate test tokens
	validToken, err := tokenGen.GenerateAdminToken(testAdminID, testCompanyID, testCompanyID, testAgentID, time.Hour)
	if err != nil {
		b.Fatalf("Failed to generate valid admin token: %v", err)
	}

	expiredToken, err := tokenGen.GenerateExpiredAdminToken(testAdminID, testCompanyID, testCompanyID, testAgentID)
	if err != nil {
		b.Fatalf("Failed to generate expired admin token: %v", err)
	}

	ctx := context.Background()

	b.Run("ValidToken", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := authService.ProcessAdminToken(ctx, validToken)
			if err != nil {
				b.Errorf("Admin token validation failed: %v", err)
			}
		}
	})

	b.Run("ExpiredToken", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := authService.ProcessAdminToken(ctx, expiredToken)
			if err == nil {
				b.Error("Expected expired admin token to fail validation")
			}
		}
	})

	b.Run("CacheHitScenario", func(b *testing.B) {
		// Pre-populate cache
		adminCtx, _ := authService.ProcessAdminToken(ctx, validToken)
		if adminCtx != nil {
			adminCache.Set(ctx, validToken, adminCtx, time.Hour)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := authService.ProcessAdminToken(ctx, validToken)
			if err != nil {
				b.Errorf("Cached admin token validation failed: %v", err)
			}
		}

		hitRatio := adminCache.GetHitRatio()
		b.Logf("Admin cache hit ratio: %.2f%%", hitRatio*100)
	})
}

// BenchmarkTokenValidationConcurrent tests concurrent token validation
func BenchmarkTokenValidationConcurrent(b *testing.B) {
	authService, _, userCache, _ := setupAuthBenchmark(b)

	// Generate multiple tokens for concurrent testing
	batchGen, err := utils.NewBatchTokenGenerator(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
	)
	if err != nil {
		b.Fatalf("Failed to create batch generator: %v", err)
	}

	tokens, err := batchGen.GenerateUserTokens(100, testCompanyID, testAgentID, time.Hour)
	if err != nil {
		b.Fatalf("Failed to generate tokens: %v", err)
	}

	ctx := context.Background()

	b.Run("ConcurrentValidation", func(b *testing.B) {
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			tokenIndex := 0
			for pb.Next() {
				token := tokens[tokenIndex%len(tokens)]
				_, err := authService.ProcessToken(ctx, token)
				if err != nil {
					b.Errorf("Concurrent token validation failed: %v", err)
				}
				tokenIndex++
			}
		})

		hitRatio := userCache.GetHitRatio()
		b.Logf("Concurrent cache hit ratio: %.2f%%", hitRatio*100)
	})
}

// BenchmarkTokenGenerationOverhead tests the overhead of token generation
func BenchmarkTokenGenerationOverhead(b *testing.B) {
	tokenGen, err := utils.NewTokenGenerator(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
	)
	if err != nil {
		b.Fatalf("Failed to create token generator: %v", err)
	}

	b.Run("UserTokenGeneration", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := tokenGen.GenerateUserToken(testCompanyID, testAgentID, testUserID, time.Hour)
			if err != nil {
				b.Errorf("User token generation failed: %v", err)
			}
		}
	})

	b.Run("AdminTokenGeneration", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := tokenGen.GenerateAdminToken(testAdminID, testCompanyID, testCompanyID, testAgentID, time.Hour)
			if err != nil {
				b.Errorf("Admin token generation failed: %v", err)
			}
		}
	})

	b.Run("BatchUserTokenGeneration", func(b *testing.B) {
		batchGen, _ := utils.NewBatchTokenGenerator(
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := batchGen.GenerateUserTokens(10, testCompanyID, testAgentID, time.Hour)
			if err != nil {
				b.Errorf("Batch token generation failed: %v", err)
			}
		}
	})
}

// BenchmarkAuthServiceScaling tests auth service performance under different loads
func BenchmarkAuthServiceScaling(b *testing.B) {
	authService, _, userCache, _ := setupAuthBenchmark(b)

	batchGen, err := utils.NewBatchTokenGenerator(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
	)
	if err != nil {
		b.Fatalf("Failed to create batch generator: %v", err)
	}

	ctx := context.Background()
	scales := []int{1, 10, 100, 1000}

	for _, scale := range scales {
		b.Run(fmt.Sprintf("Scale_%d", scale), func(b *testing.B) {
			tokens, err := batchGen.GenerateUserTokens(scale, testCompanyID, testAgentID, time.Hour)
			if err != nil {
				b.Fatalf("Failed to generate %d tokens: %v", scale, err)
			}

			userCache.Reset()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				token := tokens[i%len(tokens)]
				_, err := authService.ProcessToken(ctx, token)
				if err != nil {
					b.Errorf("Token validation failed at scale %d: %v", scale, err)
				}
			}

			hitRatio := userCache.GetHitRatio()
			b.Logf("Scale %d cache hit ratio: %.2f%%", scale, hitRatio*100)
		})
	}
}
