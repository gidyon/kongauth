package kongauth

import (
	"context"
	"sync"
	"testing"
	"time"

	redismock "github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type testAuthAPI struct {
	authCalled    int
	withKeyCalled int
	lastKey       []byte
	returnCtx     context.Context
	returnErr     error
}

func (t *testAuthAPI) Authenticator(ctx context.Context) (context.Context, error) {
	t.authCalled++
	if t.returnCtx != nil {
		return t.returnCtx, t.returnErr
	}
	return context.WithValue(ctx, testContextKey("auth"), "default"), t.returnErr
}

func (t *testAuthAPI) AuthenticatorWithKey(ctx context.Context, signingKey []byte) (context.Context, error) {
	t.withKeyCalled++
	t.lastKey = append([]byte(nil), signingKey...)
	if t.returnCtx != nil {
		return t.returnCtx, t.returnErr
	}
	return context.WithValue(ctx, testContextKey("auth_with_key"), string(signingKey)), t.returnErr
}

type testContextKey string

type noopLogger struct{}

func (noopLogger) Info(...any)             {}
func (noopLogger) Infoln(...any)           {}
func (noopLogger) Infof(string, ...any)    {}
func (noopLogger) Warning(...any)          {}
func (noopLogger) Warningln(...any)        {}
func (noopLogger) Warningf(string, ...any) {}
func (noopLogger) Error(...any)            {}
func (noopLogger) Errorln(...any)          {}
func (noopLogger) Errorf(string, ...any)   {}
func (noopLogger) Fatal(...any)            {}
func (noopLogger) Fatalln(...any)          {}
func (noopLogger) Fatalf(string, ...any)   {}
func (noopLogger) V(int) bool              { return true }

type testUser struct {
	ID     string `gorm:"column:id;primaryKey"`
	Secret string `gorm:"column:secret"`
}

func (testUser) TableName() string {
	return "users"
}

func setupTestOptions(t *testing.T) (*AuthOptions, *testAuthAPI, *gorm.DB, *redis.Client, redismock.ClientMock) {
	t.Helper()

	resetPackageState(t)

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	if err := db.AutoMigrate(&testUser{}); err != nil {
		t.Fatalf("migrate sqlite db: %v", err)
	}

	redisClient, redisMock := redismock.NewClientMock()

	authAPI := &testAuthAPI{}
	opt := &AuthOptions{
		AuthAPI: authAPI,
		SqlDB:   db,
		RedisDB: redisClient,
		Logger:  grpclog.LoggerV2(noopLogger{}),
	}

	SetRedisAuthPrefix("kongauth")
	SetUsersTable("users")
	SetTableSecretColumn("secret")
	SetCacheExpiration(time.Minute)

	return opt, authAPI, db, redisClient, redisMock
}

func resetPackageState(t *testing.T) {
	t.Helper()

	prefixOnce = &sync.Once{}
	redisAuthPrefix = ""
	prefixSet = false
	tableOnce = &sync.Once{}
	usersTable = ""
	tableSet = false
	secretOnce = &sync.Once{}
	secretColumn = ""
	secretSet = false
	expireOnce = &sync.Once{}
	cacheExpiration = 0
	expirationSet = false
	viper.Reset()
}

func TestAuthenticatorUsesDefaultAuthWhenDisabled(t *testing.T) {
	opt, authAPI, _, _, _ := setupTestOptions(t)
	viper.Set("KONG_AUTH_DISABLED", true)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(CustomIdHeader(), "user-1"))
	outCtx, err := Authenticator(ctx, opt)
	if err != nil {
		t.Fatalf("Authenticator() error = %v", err)
	}

	if authAPI.authCalled != 1 {
		t.Fatalf("Authenticator() default auth calls = %d, want 1", authAPI.authCalled)
	}
	if authAPI.withKeyCalled != 0 {
		t.Fatalf("Authenticator() keyed auth calls = %d, want 0", authAPI.withKeyCalled)
	}
	if got := outCtx.Value(testContextKey("auth")); got != "default" {
		t.Fatalf("Authenticator() default auth context value = %v, want default", got)
	}
}

func TestAuthenticatorUsesDefaultAuthWhenKongHeaderMissing(t *testing.T) {
	opt, authAPI, _, _, _ := setupTestOptions(t)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "req-1"))
	outCtx, err := Authenticator(ctx, opt)
	if err != nil {
		t.Fatalf("Authenticator() error = %v", err)
	}

	if authAPI.authCalled != 1 {
		t.Fatalf("Authenticator() default auth calls = %d, want 1", authAPI.authCalled)
	}
	if authAPI.withKeyCalled != 0 {
		t.Fatalf("Authenticator() keyed auth calls = %d, want 0", authAPI.withKeyCalled)
	}
	if got := outCtx.Value(testContextKey("auth")); got != "default" {
		t.Fatalf("Authenticator() default auth context value = %v, want default", got)
	}
}

func TestAuthenticatorUsesDefaultAuthWhenMetadataMissing(t *testing.T) {
	opt, authAPI, _, _, _ := setupTestOptions(t)

	outCtx, err := Authenticator(context.Background(), opt)
	if err != nil {
		t.Fatalf("Authenticator() error = %v", err)
	}

	if authAPI.authCalled != 1 {
		t.Fatalf("Authenticator() default auth calls = %d, want 1", authAPI.authCalled)
	}
	if authAPI.withKeyCalled != 0 {
		t.Fatalf("Authenticator() keyed auth calls = %d, want 0", authAPI.withKeyCalled)
	}
	if got := outCtx.Value(testContextKey("auth")); got != "default" {
		t.Fatalf("Authenticator() default auth context value = %v, want default", got)
	}
}

func TestAuthenticatorUsesRedisSecretWhenCached(t *testing.T) {
	opt, authAPI, _, _, redisMock := setupTestOptions(t)

	key := getRedisUserKey("user-1", redisAuthPrefix)
	redisMock.ExpectGet(key).SetVal("cached-secret")

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(CustomIdHeader(), "user-1"))
	outCtx, err := Authenticator(ctx, opt)
	if err != nil {
		t.Fatalf("Authenticator() error = %v", err)
	}

	if authAPI.authCalled != 0 {
		t.Fatalf("Authenticator() default auth calls = %d, want 0", authAPI.authCalled)
	}
	if authAPI.withKeyCalled != 1 {
		t.Fatalf("Authenticator() keyed auth calls = %d, want 1", authAPI.withKeyCalled)
	}
	if got := string(authAPI.lastKey); got != "cached-secret" {
		t.Fatalf("Authenticator() signing key = %q, want cached-secret", got)
	}
	if got := outCtx.Value(testContextKey("auth_with_key")); got != "cached-secret" {
		t.Fatalf("Authenticator() keyed auth context value = %v, want cached-secret", got)
	}
	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestAuthenticatorLoadsSecretFromDBAndCachesIt(t *testing.T) {
	opt, authAPI, db, _, redisMock := setupTestOptions(t)

	if err := db.Create(&testUser{ID: "user-2", Secret: "db-secret"}).Error; err != nil {
		t.Fatalf("insert user: %v", err)
	}

	key := getRedisUserKey("user-2", redisAuthPrefix)
	redisMock.ExpectGet(key).RedisNil()
	redisMock.ExpectSet(key, "db-secret", time.Minute).SetVal("OK")

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(CustomIdHeader(), "user-2"))
	if _, err := Authenticator(ctx, opt); err != nil {
		t.Fatalf("Authenticator() error = %v", err)
	}

	if authAPI.withKeyCalled != 1 {
		t.Fatalf("Authenticator() keyed auth calls = %d, want 1", authAPI.withKeyCalled)
	}
	if got := string(authAPI.lastKey); got != "db-secret" {
		t.Fatalf("Authenticator() signing key = %q, want db-secret", got)
	}
	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestAuthenticatorReturnsUnauthenticatedWhenUserMissing(t *testing.T) {
	opt, _, _, _, redisMock := setupTestOptions(t)

	key := getRedisUserKey("missing-user", redisAuthPrefix)
	redisMock.ExpectGet(key).RedisNil()

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(CustomIdHeader(), "missing-user"))
	_, err := Authenticator(ctx, opt)
	if err == nil {
		t.Fatal("Authenticator() error = nil, want unauthenticated error")
	}

	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("Authenticator() status code = %s, want %s", got, codes.Unauthenticated)
	}
	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestAuthenticatorReturnsInvalidArgumentWhenPackageConfigMissing(t *testing.T) {
	resetPackageState(t)

	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	redisClient, _ := redismock.NewClientMock()

	opt := &AuthOptions{
		AuthAPI: &testAuthAPI{},
		SqlDB:   db,
		RedisDB: redisClient,
		Logger:  grpclog.LoggerV2(noopLogger{}),
	}

	_, err = Authenticator(context.Background(), opt)
	if err == nil {
		t.Fatal("Authenticator() error = nil, want invalid argument")
	}

	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("Authenticator() status code = %s, want %s", got, codes.InvalidArgument)
	}
}

func TestApiContextPreservesGRPCStatusCode(t *testing.T) {
	opt, _, _, _, redisMock := setupTestOptions(t)

	key := getRedisUserKey("missing-user", redisAuthPrefix)
	redisMock.ExpectGet(key).RedisNil()

	_, cancel, err := ApiContext(metadata.Pairs(CustomIdHeader(), "missing-user"), opt)
	if cancel != nil {
		defer cancel()
	}
	if err == nil {
		t.Fatal("ApiContext() error = nil, want unauthenticated error")
	}

	if got := status.Code(err); got != codes.Unauthenticated {
		t.Fatalf("ApiContext() status code = %s, want %s", got, codes.Unauthenticated)
	}
	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}
