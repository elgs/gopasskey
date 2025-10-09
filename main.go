package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

var host = getEnv("HOST", "localhost")
var port = getEnv("PORT", "8080")
var rpName = getEnv("RP_NAME", "Webauthn")
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
	mux.HandleFunc("/api/passkey/signup_start", CORS(BeginSignup))
	mux.HandleFunc("/api/passkey/signup_finish", CORS(FinishSignup))
	mux.HandleFunc("/api/passkey/login_with_code_start", CORS(BeginLoginWithCode))
	mux.HandleFunc("/api/passkey/login_with_code_finish", CORS(FinishLoginWithCode))
	mux.HandleFunc("/api/passkey/register_start", CORS(BeginRegistration))
	mux.HandleFunc("/api/passkey/register_finish", CORS(FinishRegistration))
	mux.HandleFunc("/api/passkey/login_start", CORS(BeginLogin))
	mux.HandleFunc("/api/passkey/login_finish", CORS(FinishLogin))
	mux.HandleFunc("/api/passkey/logout", CORS(Logout))
	mux.HandleFunc("/api/passkey/credentials", CORS(GetUserCredentials))

	mux.HandleFunc("/api/passkey/private", CORS(SessionMiddleware(Private)))
	mux.HandleFunc("/api/passkey/me", CORS(SessionMiddleware(Me)))

	if err := http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), mux); err != nil {
		log.Println(err)
	}
}

func initPasskeyStore() {
	wconfig := &webauthn.Config{
		RPDisplayName: rpName,                      // Display Name for your site
		RPID:          host,                        // Generally the FQDN for your site
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
