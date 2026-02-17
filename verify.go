package telegramauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultAuthTTL is the default maximum age for auth_date.
	DefaultAuthTTL = 5 * time.Minute
	// DefaultClockSkew is the default allowed future skew for auth_date.
	DefaultClockSkew = 30 * time.Second
)

var (
	// ErrBotTokenRequired indicates that botToken is empty.
	ErrBotTokenRequired = errors.New("bot token is required")
	// ErrTelegramIDRequired indicates that id is missing.
	ErrTelegramIDRequired = errors.New("telegram id is required")
	// ErrTelegramIDInvalid indicates that id is malformed or not positive.
	ErrTelegramIDInvalid = errors.New("telegram id is invalid")
	// ErrTelegramHashRequired indicates that hash is missing.
	ErrTelegramHashRequired = errors.New("telegram hash is required")
	// ErrTelegramHashInvalid indicates that hash is malformed or does not match.
	ErrTelegramHashInvalid = errors.New("telegram hash is invalid")
	// ErrTelegramAuthDateRequired indicates that auth_date is missing.
	ErrTelegramAuthDateRequired = errors.New("telegram auth_date is required")
	// ErrTelegramAuthDateInvalid indicates that auth_date is malformed.
	ErrTelegramAuthDateInvalid = errors.New("telegram auth_date is invalid")
	// ErrTelegramAuthDateExpired indicates that auth_date is older than allowed TTL.
	ErrTelegramAuthDateExpired = errors.New("telegram auth_date is expired")
	// ErrTelegramAuthDateFuture indicates that auth_date is too far in the future.
	ErrTelegramAuthDateFuture = errors.New("telegram auth_date is from future")
)

// VerifyConfig configures VerifyWithConfig behavior.
type VerifyConfig struct {
	// AuthTTL sets maximum allowed age for auth_date.
	// Zero value uses DefaultAuthTTL.
	AuthTTL time.Duration
	// ClockSkew sets allowed future skew for auth_date.
	// Zero value uses DefaultClockSkew.
	ClockSkew time.Duration
	// Now overrides current time source.
	// Nil uses time.Now.
	Now func() time.Time
}

// AuthData contains validated Telegram user fields from callback data.
type AuthData struct {
	// UserID is Telegram user ID.
	UserID int64
	// Username is Telegram username.
	Username string
	// FirstName is Telegram first_name.
	FirstName string
	// LastName is Telegram last_name.
	LastName string
	// PhotoURL is Telegram photo_url.
	PhotoURL string
	// AuthDateUnix is Telegram auth_date unix timestamp.
	AuthDateUnix int64
}

// Verify validates Telegram callback data from a plain key/value map.
func Verify(query map[string]string, botToken string) (AuthData, error) {
	return VerifyWithConfig(query, botToken, VerifyConfig{})
}

// VerifyURLValues validates Telegram callback data from url.Values.
func VerifyURLValues(values url.Values, botToken string) (AuthData, error) {
	query := make(map[string]string, len(values))
	for key := range values {
		query[key] = values.Get(key)
	}

	return Verify(query, botToken)
}

// VerifyWithConfig validates Telegram callback data with custom options.
func VerifyWithConfig(query map[string]string, botToken string, config VerifyConfig) (AuthData, error) {
	botToken = strings.TrimSpace(botToken)
	if botToken == "" {
		return AuthData{}, ErrBotTokenRequired
	}

	authTTL := config.AuthTTL
	if authTTL <= 0 {
		authTTL = DefaultAuthTTL
	}

	clockSkew := config.ClockSkew
	if clockSkew <= 0 {
		clockSkew = DefaultClockSkew
	}

	nowFn := config.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	hash := strings.TrimSpace(query["hash"])
	if hash == "" {
		return AuthData{}, ErrTelegramHashRequired
	}

	if err := verifyHash(query, botToken, hash); err != nil {
		return AuthData{}, err
	}

	idValue := strings.TrimSpace(query["id"])
	if idValue == "" {
		return AuthData{}, ErrTelegramIDRequired
	}

	userID, err := strconv.ParseInt(idValue, 10, 64)
	if err != nil {
		return AuthData{}, fmt.Errorf("%w: %q", ErrTelegramIDInvalid, idValue)
	}

	if userID <= 0 {
		return AuthData{}, fmt.Errorf("%w: %q", ErrTelegramIDInvalid, idValue)
	}

	authDateValue := strings.TrimSpace(query["auth_date"])
	if authDateValue == "" {
		return AuthData{}, ErrTelegramAuthDateRequired
	}

	authDateUnix, err := strconv.ParseInt(authDateValue, 10, 64)
	if err != nil {
		return AuthData{}, fmt.Errorf("%w: %q", ErrTelegramAuthDateInvalid, authDateValue)
	}

	authDate := time.Unix(authDateUnix, 0)
	now := nowFn()
	if authDate.After(now.Add(clockSkew)) {
		return AuthData{}, ErrTelegramAuthDateFuture
	}

	if now.Sub(authDate) > authTTL {
		return AuthData{}, ErrTelegramAuthDateExpired
	}

	return AuthData{
		UserID:       userID,
		Username:     query["username"],
		FirstName:    query["first_name"],
		LastName:     query["last_name"],
		PhotoURL:     query["photo_url"],
		AuthDateUnix: authDateUnix,
	}, nil
}

func verifyHash(query map[string]string, botToken, expectedHash string) error {
	expectedHashBytes, err := hex.DecodeString(strings.TrimSpace(expectedHash))
	if err != nil {
		return ErrTelegramHashInvalid
	}

	dataCheckPairs := make([]string, 0, len(query))
	for key, value := range query {
		if key == "hash" {
			continue
		}

		dataCheckPairs = append(dataCheckPairs, fmt.Sprintf("%s=%s", key, value))
	}

	sort.Strings(dataCheckPairs)
	dataCheckString := strings.Join(dataCheckPairs, "\n")

	secret := sha256.Sum256([]byte(botToken))
	hasher := hmac.New(sha256.New, secret[:])
	_, _ = hasher.Write([]byte(dataCheckString))
	calculatedHashBytes := hasher.Sum(nil)

	if !hmac.Equal(calculatedHashBytes, expectedHashBytes) {
		return ErrTelegramHashInvalid
	}

	return nil
}
