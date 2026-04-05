package main

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/go-webauthn/webauthn/webauthn"
"github.com/redis/go-redis/v9"
)

var env = os.Getenv("ENV")
var host = getEnv("HOST", "localhost")
var port = getEnv("PORT", "8080")
var rpName = getEnv("RP_NAME", "Webauthn")
var rpId = getEnv("RP_ID", host)
var origins = getEnv("ORIGINS", "")
var redisURL = getEnv("REDIS_URL", "localhost:6379")
var dbUser = getEnv("DB_USER", "root")
var dbPassword = getEnv("DB_PASSWORD", "password")
var dbHost = getEnv("DB_HOST", "localhost")
var dbPort = getEnv("DB_PORT", "3306")
var dbName = getEnv("DB_NAME", "appdb")

var ctx = context.Background() // go's ugliest thing
var err error
var webAuthn *webauthn.WebAuthn
var db *sql.DB
var redisClient *redis.Client

//go:embed web/dist
var web embed.FS
var staticFS fs.FS

func main() {
	initRedis()
	defer redisClient.Close()
	initDB()
	defer db.Close()
	initPasskeyStore()
	initApiServer()
}

func initApiServer() {

	mux := http.NewServeMux()

	if env == "dev" {
		staticFS = os.DirFS("web/build")
		log.Println("Serving static files from disk (hot reload enabled)")
	} else {
		var err error
		staticFS, err = fs.Sub(web, "web/dist")
		if err != nil {
			log.Fatal(err)
		}
	}

	mux.Handle("GET /", http.FileServer(http.FS(staticFS)))

	mux.HandleFunc("POST /api/pub/login_start", BeginEmailLogin)
	mux.HandleFunc("GET /api/pub/verify_login", VerifyLoginLink)
	mux.HandleFunc("POST /api/pub/register_start", BeginRegistration)
	mux.HandleFunc("POST /api/pub/register_finish", FinishRegistration)
	mux.HandleFunc("POST /api/pub/register_confirm", ConfirmRegistration)
	mux.HandleFunc("POST /api/pub/passkey_login_start", BeginLogin)
	mux.HandleFunc("POST /api/pub/passkey_login_finish", FinishLogin)

	mux.HandleFunc("GET /api/pub/sso/authorize", SSOAuthorize)
	mux.HandleFunc("POST /api/pub/sso/token", SSOToken)
	mux.HandleFunc("GET /api/pub/sso/validate", SSOValidate)
	mux.HandleFunc("POST /api/pub/sso/revoke", SSORevoke)
	mux.HandleFunc("GET /api/pub/sso/logout", SSOLogout)

	mux.HandleFunc("POST /api/logout", Logout)
	mux.HandleFunc("GET /api/credentials", GetUserCredentials)
	mux.HandleFunc("DELETE /api/credentials", DeleteUserCredential)
	mux.HandleFunc("PUT /api/profile", UpdateProfile)
	mux.HandleFunc("GET /api/me", Me)
	mux.HandleFunc("GET /api/sso/sessions", SSOSessions)
	mux.HandleFunc("DELETE /api/sso/sessions", SSORevokeSession)

	handler := CORS(Auth(mux))
	addr := fmt.Sprintf("%s:%s", host, port)
	log.Printf("Listening on http://%s\n", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Println(err)
	}
}

func initPasskeyStore() {
	wconfig := &webauthn.Config{
		RPDisplayName: rpName,                      // Display Name for your site
		RPID:          rpId,                        // Generally the FQDN for your site
		RPOrigins:     strings.Split(origins, ","), // The origin URLs allowed for WebAuthn
	}
	webAuthn, err = webauthn.New(wconfig)
	if err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}
}

func initDB() {
	var err error
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true", dbUser, dbPassword, dbHost, dbPort, dbName)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}

	if err = db.Ping(); err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}

	fmt.Println("[INFO] connected to database")
}

func initRedis() {
	redisOpts := &redis.Options{
		Addr: redisURL,
	}
	redisClient = redis.NewClient(redisOpts)
}
