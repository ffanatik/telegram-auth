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
	"testing"
	"time"
)

const testBotToken = "test-token"

func TestVerifyWithConfigValid(t *testing.T) {
	now := time.Unix(1800000000, 0)
	query := map[string]string{
		"id":         "42",
		"auth_date":  strconv.FormatInt(now.Unix(), 10),
		"username":   "john_doe",
		"first_name": "John",
		"last_name":  "Doe",
		"photo_url":  "https://example.com/avatar.jpg",
	}
	query["hash"] = signQuery(query)

	authData, err := VerifyWithConfig(query, testBotToken, VerifyConfig{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("VerifyWithConfig() error = %v", err)
	}

	if authData.UserID != 42 {
		t.Fatalf("UserID = %d, want %d", authData.UserID, 42)
	}

	if authData.AuthDateUnix != now.Unix() {
		t.Fatalf("AuthDateUnix = %d, want %d", authData.AuthDateUnix, now.Unix())
	}

	if authData.Username != "john_doe" {
		t.Fatalf("Username = %q, want %q", authData.Username, "john_doe")
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	query := map[string]string{
		"id":        "42",
		"auth_date": strconv.FormatInt(time.Now().Unix(), 10),
		"hash":      "deadbeef",
	}

	_, err := Verify(query, testBotToken)
	if !errors.Is(err, ErrTelegramHashInvalid) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrTelegramHashInvalid)
	}
}

func TestVerifyInvalidUserIDRange(t *testing.T) {
	tests := []string{"0", "-1"}

	for _, userID := range tests {
		t.Run(userID, func(t *testing.T) {
			query := map[string]string{
				"id":        userID,
				"auth_date": strconv.FormatInt(time.Now().Unix(), 10),
			}
			query["hash"] = signQuery(query)

			_, err := Verify(query, testBotToken)
			if !errors.Is(err, ErrTelegramIDInvalid) {
				t.Fatalf("Verify() error = %v, want %v", err, ErrTelegramIDInvalid)
			}
		})
	}
}

func TestVerifyURLValues(t *testing.T) {
	nowUnix := time.Now().Unix()
	values := url.Values{
		"id":         {"42", "999"},
		"auth_date":  {strconv.FormatInt(nowUnix, 10)},
		"username":   {"john_doe"},
		"first_name": {"John"},
	}

	queryForHash := make(map[string]string, len(values))
	for key := range values {
		queryForHash[key] = values.Get(key)
	}
	values.Set("hash", signQuery(queryForHash))

	authData, err := VerifyURLValues(values, testBotToken)
	if err != nil {
		t.Fatalf("VerifyURLValues() error = %v", err)
	}

	if authData.UserID != 42 {
		t.Fatalf("UserID = %d, want %d", authData.UserID, 42)
	}
}

func TestVerifyMissingRequiredFields(t *testing.T) {
	nowUnix := strconv.FormatInt(time.Now().Unix(), 10)
	tests := []struct {
		name    string
		query   map[string]string
		wantErr error
	}{
		{
			name: "missing hash",
			query: map[string]string{
				"id":        "42",
				"auth_date": nowUnix,
			},
			wantErr: ErrTelegramHashRequired,
		},
		{
			name: "missing id",
			query: map[string]string{
				"auth_date": nowUnix,
			},
			wantErr: ErrTelegramIDRequired,
		},
		{
			name: "missing auth_date",
			query: map[string]string{
				"id": "42",
			},
			wantErr: ErrTelegramAuthDateRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name != "missing hash" {
				tt.query["hash"] = signQuery(tt.query)
			}

			_, err := Verify(tt.query, testBotToken)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyExpired(t *testing.T) {
	now := time.Unix(1800000000, 0)
	query := map[string]string{
		"id":        "42",
		"auth_date": strconv.FormatInt(now.Add(-DefaultAuthTTL-time.Second).Unix(), 10),
	}
	query["hash"] = signQuery(query)

	_, err := VerifyWithConfig(query, testBotToken, VerifyConfig{Now: func() time.Time { return now }})
	if !errors.Is(err, ErrTelegramAuthDateExpired) {
		t.Fatalf("VerifyWithConfig() error = %v, want %v", err, ErrTelegramAuthDateExpired)
	}
}

func TestVerifyFuture(t *testing.T) {
	now := time.Unix(1800000000, 0)
	query := map[string]string{
		"id":        "42",
		"auth_date": strconv.FormatInt(now.Add(DefaultClockSkew+time.Second).Unix(), 10),
	}
	query["hash"] = signQuery(query)

	_, err := VerifyWithConfig(query, testBotToken, VerifyConfig{Now: func() time.Time { return now }})
	if !errors.Is(err, ErrTelegramAuthDateFuture) {
		t.Fatalf("VerifyWithConfig() error = %v, want %v", err, ErrTelegramAuthDateFuture)
	}
}

func TestVerifyBotTokenRequired(t *testing.T) {
	query := map[string]string{
		"id":        "42",
		"auth_date": strconv.FormatInt(time.Now().Unix(), 10),
	}
	query["hash"] = signQuery(query)

	_, err := Verify(query, "")
	if !errors.Is(err, ErrBotTokenRequired) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrBotTokenRequired)
	}
}

func signQuery(query map[string]string) string {
	dataCheckPairs := make([]string, 0, len(query))
	for key, value := range query {
		if key == "hash" {
			continue
		}

		dataCheckPairs = append(dataCheckPairs, fmt.Sprintf("%s=%s", key, value))
	}

	sort.Strings(dataCheckPairs)
	dataCheckString := strings.Join(dataCheckPairs, "\n")

	secret := sha256.Sum256([]byte(testBotToken))
	hasher := hmac.New(sha256.New, secret[:])
	_, _ = hasher.Write([]byte(dataCheckString))

	return hex.EncodeToString(hasher.Sum(nil))
}
