package jwtutil

import (
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/levigross/logger/logger"
	"go.uber.org/zap"
)

const (
	JWTFieldMatch = "sub"
)

var (
	log           = logger.WithName("jwtutil")
	ErrKeyInvalid = fmt.Errorf("jwtutil: Key does not have the expected parameters")
)

type Auth struct {
	jose.JSONWebKeySet
}

func (a *Auth) ValidateJWT(jwt *jwt.JSONWebToken) (string, error) {
	for _, header := range jwt.Headers {
		jwks := a.Key(header.KeyID)
		for _, jwk := range jwks {
			claims := map[string]string{}
			if err := jwt.Claims(jwk, &claims); err != nil {
				log.Error("JWT claims cannot be verified", zap.Error(err))
				return "", err
			}
			return claims[JWTFieldMatch], nil
		}
	}
	return "", fmt.Errorf("jwtutil: JWT doesn't match any provided keys")
}

func NewAuth(jwkBytes []byte) (*Auth, error) {
	a := &Auth{}
	if err := json.Unmarshal(jwkBytes, a); err != nil {
		log.Error("Unable to unmarshal JWK bytes", zap.Error(err))
		return nil, err
	}
	// Validate the keys
	for _, k := range a.Keys {
		if !k.Valid() || !k.IsPublic() {
			log.Error("Key is not valid",
				zap.Any("key", k),
				zap.Bool("isPublic", k.IsPublic()),
				zap.Bool("isValid", k.Valid()),
			)
			return nil, ErrKeyInvalid
		}
	}
	return a, nil
}
