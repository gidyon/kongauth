package kongauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

var (
	prefixOnce      = &sync.Once{}
	redisAuthPrefix string
	prefixSet       bool
	tableOnce       = &sync.Once{}
	usersTable      string
	tableSet        bool
	secretOnce      = &sync.Once{}
	secretColumn    string
	secretSet       bool
	expireOnce      = &sync.Once{}
	cacheExpiration time.Duration
	expirationSet   bool
)

// SetRedisAuthPrefix sets the redis auth prefix.
// 🔐 Happens once even when called multiple times.
func SetRedisAuthPrefix(prefix string) {
	prefixOnce.Do(func() {
		redisAuthPrefix = prefix
		prefixSet = true
	})
}

// SetUsersTable sets the users table to use.
// 🧾 Happens once even when called multiple times.
func SetUsersTable(tableName string) {
	tableOnce.Do(func() {
		usersTable = tableName
		tableSet = true
	})
}

// SetTableSecretColumn sets the users column to use.
// 🕵️ Happens once even when called multiple times.
func SetTableSecretColumn(column string) {
	secretOnce.Do(func() {
		secretColumn = column
		secretSet = true
	})
}

// SetCacheExpiration sets the expiration.
// ⏳ Happens once even when called multiple times.
func SetCacheExpiration(dur time.Duration) {
	expireOnce.Do(func() {
		cacheExpiration = dur
		expirationSet = true
	})
}

// AuthAPI is an interface that does authentication
// 🔐 Contract for authentication

// AuthOptions contains options required for doing kong auth
// 🧰 Configuration for Kong Auth

type AuthAPI interface {
	Authenticator(ctx context.Context) (context.Context, error)
	AuthenticatorWithKey(ctx context.Context, signingKey []byte) (context.Context, error)
}

type AuthOptions struct {
	AuthAPI AuthAPI
	SqlDB   *gorm.DB
	RedisDB *redis.Client
	Logger  grpclog.LoggerV2
}

func validateAuthOptions(opt *AuthOptions) error {
	switch {
	case opt == nil:
		return status.Errorf(codes.InvalidArgument, "missing message field: auth options")
	case opt.AuthAPI == nil:
		return status.Errorf(codes.InvalidArgument, "missing message field: auth api")
	case opt.SqlDB == nil:
		return status.Errorf(codes.InvalidArgument, "missing message field: sql db")
	case opt.RedisDB == nil:
		return status.Errorf(codes.InvalidArgument, "missing message field: redis")
	case opt.Logger == nil:
		return status.Errorf(codes.InvalidArgument, "missing message field: logger")
	}
	return nil
}

func validatePackageConfig() error {
	switch {
	case !prefixSet || redisAuthPrefix == "":
		return status.Error(codes.InvalidArgument, "missing kongauth config: redis auth prefix")
	case !tableSet || usersTable == "":
		return status.Error(codes.InvalidArgument, "missing kongauth config: users table")
	case !secretSet || secretColumn == "":
		return status.Error(codes.InvalidArgument, "missing kongauth config: secret column")
	case !expirationSet:
		return status.Error(codes.InvalidArgument, "missing kongauth config: cache expiration")
	case cacheExpiration < 0:
		return status.Error(codes.InvalidArgument, "invalid kongauth config: cache expiration must be non-negative")
	}

	return nil
}

// Authenticator is a helper to authenticate requests sent to upstream from Kong
func Authenticator(ctx context.Context, opt *AuthOptions) (context.Context, error) {
	err := validateAuthOptions(opt)
	if err != nil {
		return nil, err
	}
	if err := validatePackageConfig(); err != nil {
		return nil, err
	}

	// 🚫 If kong auth is disabled we use default authentication
	if viper.GetBool("KONG_AUTH_DISABLED") {
		return opt.AuthAPI.Authenticator(ctx)
	}

	// 📨 Get request headers from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return opt.AuthAPI.Authenticator(ctx)
	}

	// 🧭 Get forwarded kong header
	customIds := md.Get(CustomIdHeader())
	if len(customIds) == 0 {
		// 🛂 Request bypassed Kong – use default authenticator
		return opt.AuthAPI.Authenticator(ctx)
	}

	// 🔑 Key to redis user
	key := getRedisUserKey(customIds[0], redisAuthPrefix)

	// 🧠 Get consumer secret from redis or fallback to DB
	secret, err := opt.RedisDB.Get(ctx, key).Result()
	switch {
	case err == nil:
		// ✅ Found in Redis, proceed
	case errors.Is(err, redis.Nil):
		row := opt.SqlDB.Table(usersTable).Select(secretColumn).Where("id=?", customIds[0]).Row()
		err = row.Scan(&secret)
		if err != nil {
			opt.Logger.Errorln("❌ KongAuth Failed to get user from DB: ", err)
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}
		err = opt.RedisDB.Set(ctx, key, secret, cacheExpiration).Err()
		if err != nil {
			opt.Logger.Errorln("⚠️ KongAuth Failed to cache user in Redis: ", err)
			return opt.AuthAPI.AuthenticatorWithKey(ctx, []byte(secret))
		}
	default:
		opt.Logger.Errorln("🚨 KongAuth Redis error: ", err)
		return nil, status.Error(codes.Internal, "request could not be completed")
	}

	// 🗝️ Use the secret key while decoding token
	return opt.AuthAPI.AuthenticatorWithKey(ctx, []byte(secret))
}

func CustomIdHeader() string {
	return "X-Consumer-Custom-ID"
}

func ApiContext(md metadata.MD, opt *AuthOptions) (context.Context, context.CancelFunc, error) {
	err := validateAuthOptions(opt)
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(), md))
	ctx, err = Authenticator(ctx, opt)
	if err != nil {
		return nil, cancel, authorizationError(err)
	}

	return ctx, cancel, nil
}

func ApiContextWithTimeout(md metadata.MD, dur time.Duration, opt *AuthOptions) (context.Context, context.CancelFunc, error) {
	err := validateAuthOptions(opt)
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), dur)
	ctx = metadata.NewIncomingContext(ctx, md)
	ctx, err = Authenticator(ctx, opt)
	if err != nil {
		return nil, cancel, authorizationError(err)
	}

	return ctx, cancel, nil
}

func getRedisUserKey(clientKey, redisAuthPrefix string) string {
	return fmt.Sprintf("%s:%s", redisAuthPrefix, clientKey)
}

func authorizationError(err error) error {
	if s, ok := status.FromError(err); ok {
		return status.Errorf(s.Code(), "authorization failed: %s", s.Message())
	}

	return fmt.Errorf("authorization failed: %w", err)
}
