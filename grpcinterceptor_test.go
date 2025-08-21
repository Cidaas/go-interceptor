package cidaasinterceptor

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestNewGrpcInterceptor(t *testing.T) {
	opts := Options{
		BaseURI:  "http://127.0.0.1:8080", // Use local test server
		ClientID: "test-client",
		Debug:    true,
	}

	interceptor, err := NewGrpcInterceptor(opts)
	if err != nil {
		t.Fatalf("Failed to create gRPC interceptor: %v", err)
	}

	if interceptor == nil {
		t.Fatal("Interceptor should not be nil")
	}

	if interceptor.Options.BaseURI != opts.BaseURI {
		t.Errorf("Expected BaseURI %s, got %s", opts.BaseURI, interceptor.Options.BaseURI)
	}
}

func TestGetTokenFromGrpcMetadata(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectError   bool
		expectedToken string
	}{
		{
			name:          "valid bearer token",
			authHeader:    "Bearer test-token",
			expectError:   false,
			expectedToken: "test-token",
		},
		{
			name:        "missing authorization header",
			authHeader:  "",
			expectError: true,
		},
		{
			name:        "invalid token format",
			authHeader:  "Invalid test-token",
			expectError: true,
		},
		{
			name:        "empty bearer token",
			authHeader:  "Bearer ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.authHeader != "" {
				md := metadata.New(map[string]string{
					"authorization": tt.authHeader,
				})
				ctx = metadata.NewIncomingContext(ctx, md)
			}

			token, err := getTokenFromGrpcMetadata(ctx)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token != tt.expectedToken {
					t.Errorf("Expected token %s, got %s", tt.expectedToken, token)
				}
			}
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectError   bool
		expectedToken string
	}{
		{
			name:          "valid bearer token",
			authHeader:    "Bearer test-token",
			expectError:   false,
			expectedToken: "test-token",
		},
		{
			name:        "empty header",
			authHeader:  "",
			expectError: true,
		},
		{
			name:        "invalid format",
			authHeader:  "Invalid test-token",
			expectError: true,
		},
		{
			name:          "case insensitive bearer",
			authHeader:    "bearer test-token",
			expectError:   false,
			expectedToken: "test-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := extractBearerToken(tt.authHeader)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token != tt.expectedToken {
					t.Errorf("Expected token %s, got %s", tt.expectedToken, token)
				}
			}
		})
	}
}

func TestGetTokenDataFromGrpcContext(t *testing.T) {
	// Test with token data in context
	tokenData := TokenData{
		Sub: "test-subject",
		Aud: "test-audience",
	}
	ctx := context.WithValue(context.Background(), GrpcTokenDataKey, tokenData)

	retrievedTokenData, ok := GetTokenDataFromGrpcContext(ctx)
	if !ok {
		t.Fatal("Expected to retrieve token data from context")
	}

	if retrievedTokenData.Sub != tokenData.Sub {
		t.Errorf("Expected Sub %s, got %s", tokenData.Sub, retrievedTokenData.Sub)
	}

	if retrievedTokenData.Aud != tokenData.Aud {
		t.Errorf("Expected Aud %s, got %s", tokenData.Aud, retrievedTokenData.Aud)
	}

	// Test with no token data in context
	emptyCtx := context.Background()
	_, ok = GetTokenDataFromGrpcContext(emptyCtx)
	if ok {
		t.Error("Expected no token data to be found in empty context")
	}
}

func TestGetSubFromGrpcContext(t *testing.T) {
	tokenData := TokenData{
		Sub: "test-subject",
		Aud: "test-audience",
	}
	ctx := context.WithValue(context.Background(), GrpcTokenDataKey, tokenData)

	sub, ok := GetSubFromGrpcContext(ctx)
	if !ok {
		t.Fatal("Expected to retrieve sub from context")
	}

	if sub != tokenData.Sub {
		t.Errorf("Expected Sub %s, got %s", tokenData.Sub, sub)
	}
}

func TestGetAudFromGrpcContext(t *testing.T) {
	tokenData := TokenData{
		Sub: "test-subject",
		Aud: "test-audience",
	}
	ctx := context.WithValue(context.Background(), GrpcTokenDataKey, tokenData)

	aud, ok := GetAudFromGrpcContext(ctx)
	if !ok {
		t.Fatal("Expected to retrieve aud from context")
	}

	if aud != tokenData.Aud {
		t.Errorf("Expected Aud %s, got %s", tokenData.Aud, aud)
	}
}

// Mock handler for testing interceptors
func mockHandler(ctx context.Context, req interface{}) (interface{}, error) {
	return "success", nil
}

func TestVerifyTokenBySignatureInterceptor(t *testing.T) {
	opts := Options{
		BaseURI:  "http://127.0.0.1:8080", // Use local test server
		ClientID: "test-client",
		Debug:    true,
	}

	interceptor, err := NewGrpcInterceptor(opts)
	if err != nil {
		t.Fatalf("Failed to create gRPC interceptor: %v", err)
	}

	securityOpts := SecurityOptions{
		Scopes:                []string{"test-scope"},
		StrictScopeValidation: false,
	}

	// Test with missing authorization header
	ctx := context.Background()
	req := "test-request"
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/TestMethod",
	}

	interceptorFunc := interceptor.VerifyTokenBySignature(securityOpts)
	_, err = interceptorFunc(ctx, req, info, mockHandler)

	if err == nil {
		t.Error("Expected error for missing authorization header")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated error, got %v", st.Code())
	}
}

func TestVerifyTokenByIntrospectInterceptor(t *testing.T) {
	opts := Options{
		BaseURI:  "http://127.0.0.1:8080", // Use local test server
		ClientID: "test-client",
		Debug:    true,
	}

	interceptor, err := NewGrpcInterceptor(opts)
	if err != nil {
		t.Fatalf("Failed to create gRPC interceptor: %v", err)
	}

	securityOpts := SecurityOptions{
		Scopes:                []string{"test-scope"},
		StrictScopeValidation: false,
	}

	// Test with missing authorization header
	ctx := context.Background()
	req := "test-request"
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/TestMethod",
	}

	interceptorFunc := interceptor.VerifyTokenByIntrospect(securityOpts)
	_, err = interceptorFunc(ctx, req, info, mockHandler)

	if err == nil {
		t.Error("Expected error for missing authorization header")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated error, got %v", st.Code())
	}
}
