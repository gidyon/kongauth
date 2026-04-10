// Package kongauth provides gRPC authentication helpers for services deployed
// behind Kong.
//
// The package reads the Kong consumer ID from incoming gRPC metadata, resolves
// the consumer secret from Redis or SQL, and hands that secret to an
// application-defined authenticator for downstream authorization.
package kongauth
