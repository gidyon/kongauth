package kongauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gidyon/micro/utils/errs"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

func getRedisUserKey(clientKey, redisAuthPrefix string) string {
	return fmt.Sprintf("%s:%s", redisAuthPrefix, clientKey)
}

// AuthAPI is an interface that does authentication
type AuthAPI interface {
	Authenticator(ctx context.Context) (context.Context, error)
	AuthenticatorWithKey(ctx context.Context, signingKey []byte) (context.Context, error)
}

// AuthOptions contains options required for doing kong auth
type AuthOptions struct {
	AuthAPI         AuthAPI
	SqlDB           *gorm.DB
	RedisDB         *redis.Client
	Logger          grpclog.LoggerV2
	CacheExpiration time.Duration
	RedisAuthPrefix string
	UsersTable      string
	SecretColumn    string
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
	case opt.RedisAuthPrefix == "":
		return status.Error(codes.InvalidArgument, "missing redis user key prefix")
	case opt.UsersTable == "":
		return status.Error(codes.InvalidArgument, "missing users table")
	case opt.SecretColumn == "":
		return status.Error(codes.InvalidArgument, "missing users secret column")
	default:
		if opt.CacheExpiration == 0 {
			opt.CacheExpiration = time.Hour * 3
		}
	}
	return nil
}

// Authenticator is a helper to authenticate requests sent to upstream from Kong
func Authenticator(ctx context.Context, opt *AuthOptions) (context.Context, error) {
	err := validateAuthOptions(opt)
	if err != nil {
		return nil, err
	}

	// If kong auth is disabled we use default authentication
	if viper.GetBool("KONG_AUTH_DISABLED") {
		return opt.AuthAPI.Authenticator(ctx)
	}

	// Get request headers from context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "could not complete request due to missing headers")
	}

	// Get forwarded kong header
	customIds := md.Get(CustomIdHeader())
	if len(customIds) == 0 {
		// Means the request has not passed through kong
		// We use our default authenticator
		return opt.AuthAPI.Authenticator(ctx)
	}

	// Key to redis user
	key := getRedisUserKey(customIds[0], opt.RedisAuthPrefix)

	// Get consumer secret from redis for the particular
	secret, err := opt.RedisDB.Get(ctx, key).Result()
	switch {
	case err == nil:
	case errors.Is(err, redis.Nil):
		// Get user from db and save to redis
		row := opt.SqlDB.Table(opt.UsersTable).Select("%s", opt.SecretColumn).Where("id=?", customIds[0]).Row()
		// Scan data
		err = row.Scan(&secret)
		switch {
		case err == nil:
			// Save to redis with 3 hour expiration
			err = opt.RedisDB.Set(ctx, key, secret, opt.CacheExpiration).Err()
			if err != nil {
				opt.Logger.Errorln(err)
				return nil, errs.WrapMessage(codes.Internal, "could not complete the request")
			}
		default:
			opt.Logger.Errorln(err)
			return nil, status.Error(codes.Internal, "could not complete the request")
		}
	default:
		// Decode the jwt using default jwt key
		opt.Logger.Errorln(err)
		return nil, status.Error(codes.Internal, "could not complete the request")
	}

	// Use the key while decoding token
	return opt.AuthAPI.AuthenticatorWithKey(ctx, []byte(secret))
}

func CustomIdHeader() string {
	return "X-Consumer-Custom-ID"
}

func ApiContext(md metadata.MD, opt *AuthOptions) (context.Context, context.CancelFunc, error) {
	// Validate options
	err := validateAuthOptions(opt)
	if err != nil {
		return nil, nil, err
	}

	// Communication context
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(), md))

	// Authenticate the context using kong auth
	ctx, err = Authenticator(ctx, opt)
	if err != nil {
		return nil, cancel, fmt.Errorf("failed to authorize request: %v", err)
	}

	return ctx, cancel, nil
}

func ApiContextWithTimeout(md metadata.MD, dur time.Duration, opt *AuthOptions) (context.Context, context.CancelFunc, error) {
	// Validate options
	err := validateAuthOptions(opt)
	if err != nil {
		return nil, nil, err
	}

	// Communication context
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	ctx = metadata.NewIncomingContext(ctx, md)

	// Authenticate the context using kong auth
	ctx, err = Authenticator(ctx, opt)
	if err != nil {
		return nil, cancel, fmt.Errorf("failed to authorize request: %v", err)
	}

	return ctx, cancel, nil
}
