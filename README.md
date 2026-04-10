# kongauth

`kongauth` is a small gRPC authentication helper for services that sit behind Kong.

When Kong forwards a request, it attaches the consumer identifier in the
`X-Consumer-Custom-ID` header. This package uses that header to look up the
consumer's secret, then passes that secret to your application-specific
authenticator so downstream services can validate the request as the Kong
consumer.

## How It Works

1. Kong authenticates the inbound request.
2. Kong forwards the request to your gRPC service with
   `X-Consumer-Custom-ID`.
3. `kongauth.Authenticator` reads that header from gRPC metadata.
4. The package looks up the consumer secret in Redis.
5. On a cache miss, it loads the secret from SQL and stores it back in Redis.
6. The secret is passed to `AuthAPI.AuthenticatorWithKey`.

If Kong auth is disabled, or the Kong header is missing, the package falls back
to `AuthAPI.Authenticator`.

## Main Types

- `AuthAPI`: your application hook for default auth and key-based auth.
- `AuthOptions`: wiring for SQL, Redis, and logging.
- `Authenticator`: authenticates an incoming gRPC context.
- `ApiContext` and `ApiContextWithTimeout`: helpers for building authenticated
  gRPC contexts from metadata.

## Required Configuration

Set these once during process startup before handling requests:

- `SetRedisAuthPrefix`
- `SetUsersTable`
- `SetTableSecretColumn`
- `SetCacheExpiration`

`AuthOptions` also requires:

- `AuthAPI`
- `SqlDB`
- `RedisDB`
- `Logger`

## Example

```go
kongauth.SetRedisAuthPrefix("kongauth")
kongauth.SetUsersTable("users")
kongauth.SetTableSecretColumn("secret")
kongauth.SetCacheExpiration(5 * time.Minute)

opt := &kongauth.AuthOptions{
	AuthAPI: myAuthAPI,
	SqlDB:   sqlDB,
	RedisDB: redisDB,
	Logger:  logger,
}

func unaryInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	authCtx, err := kongauth.Authenticator(ctx, opt)
	if err != nil {
		return nil, err
	}
	return handler(authCtx, req)
}
```

## Header Used

- `X-Consumer-Custom-ID`

This should match the consumer identifier Kong forwards for the authenticated
request.
