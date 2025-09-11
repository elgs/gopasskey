module github.com/elgs/go-passkey

go 1.25

replace github.com/elgs/gosqlcrud => ../gosqlcrud

require (
	github.com/elgs/gosqlcrud v0.0.0-20250910094801-55167c4527dc
	github.com/go-sql-driver/mysql v1.9.3
	github.com/go-webauthn/webauthn v0.13.4
	github.com/google/uuid v1.6.0
	github.com/redis/go-redis/v9 v9.14.0
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-webauthn/x v0.1.24 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/go-tpm v0.9.5 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
)
