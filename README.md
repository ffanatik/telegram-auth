# telegram-auth

`telegram-auth` is a tiny Go library for validating Telegram Login Widget callback data.

It verifies:

- callback signature (`hash`)
- required fields (`id`, `auth_date`, `hash`)
- `id` format and range (`> 0`)
- `auth_date` freshness (TTL and clock skew)

## Install

```bash
go get github.com/ffanatik/telegram-auth
```

## Quick example

```go
package main

import (
	"fmt"
	"net/http"
	"os"

	telegramauth "github.com/ffanatik/telegram-auth"
)

func callback(w http.ResponseWriter, r *http.Request) {
	auth, err := telegramauth.VerifyURLValues(r.URL.Query(), os.Getenv("TELEGRAM_BOT_TOKEN"))
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Hello, %s (%d)", auth.FirstName, auth.UserID)
}
```

## API

- `Verify(map[string]string, botToken string)`
- `VerifyURLValues(url.Values, botToken string)`
- `VerifyWithConfig(map[string]string, botToken string, config VerifyConfig)`

Default values:

- `DefaultAuthTTL = 5 * time.Minute`
- `DefaultClockSkew = 30 * time.Second`

All exported validation errors are sentinel errors and can be checked with `errors.Is`.
