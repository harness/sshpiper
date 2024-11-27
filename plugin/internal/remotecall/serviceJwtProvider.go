package remotecall

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	// defaultJWTValidFor specifies for how long a jwt token is valid.
	defaultJWTValidFor = 1 * time.Second
)

type ServiceJWTProvider struct {
	serviceIdentity string
	signingKey      []byte
	jwtValidFor     time.Duration

	// cached token
	currentJWT   string
	refreshAfter time.Time
	lock         sync.Mutex
}

func NewServiceJWTProvider(serviceIdentity string, secret []byte,
	jwtValidFor time.Duration) (*ServiceJWTProvider, error) {
	if serviceIdentity == "" {
		return nil, fmt.Errorf("serviceIdentity used to identify JWT tokens can't be empty")
	}

	if len(secret) == 0 {
		return nil, fmt.Errorf("secret used to sign JWT tokens can't be empty")
	}

	if jwtValidFor <= 0 {
		jwtValidFor = defaultJWTValidFor
	}

	return &ServiceJWTProvider{
		serviceIdentity: serviceIdentity,
		signingKey:      secret,
		jwtValidFor:     jwtValidFor,
	}, nil
}

func (p *ServiceJWTProvider) GetJWT() (string, error) {
	now := time.Now().UTC()
	// avoid lock for in case of fresh token
	if now.Before(p.refreshAfter) {
		return p.currentJWT, nil
	}

	// generate new token (in lock)
	p.lock.Lock()
	defer p.lock.Unlock()

	// check if token already got refreshed while we waited for lock
	if now.Before(p.refreshAfter) {
		return p.currentJWT, nil
	}

	expiresAt := now.Add(p.jwtValidFor)
	newToken, err := NewServiceJWT(p.serviceIdentity, p.signingKey, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to generat new token: %w", err)
	}

	p.currentJWT = newToken
	p.refreshAfter = now.Add(p.jwtValidFor / 2) // refresh after half of life is reached

	return p.currentJWT, nil
}

func (p *ServiceJWTProvider) Provide() (string, error) {
	return p.GetJWT()
}

func NewServiceJWT(identity string, signingKey []byte, expiresAt time.Time) (string, error) {
	now := time.Now()
	claims := JWTClaims{
		Type: "SERVICE",
		Name: identity,
		StandardClaims: jwt.StandardClaims{
			Issuer:    "Harness Inc",
			IssuedAt:  now.Unix(),
			ExpiresAt: expiresAt.Unix(),
			NotBefore: now.Add(-time.Hour * 1).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}

	return fmt.Sprintf("%s %s", identity, signedToken), nil
}
