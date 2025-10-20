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
	"github.com/justinas/alice"
	"github.com/redis/go-redis/v9"
)

var env = os.Getenv("ENV")
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

	chain := alice.New(CORS, Auth)

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

	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	mux.Handle("/api/pub/signup_start", chain.ThenFunc(BeginSignup))
	mux.Handle("/api/pub/signup_finish", chain.ThenFunc(FinishSignup))
	mux.Handle("/api/pub/login_with_code_start", chain.ThenFunc(BeginLoginWithCode))
	mux.Handle("/api/pub/login_with_code_finish", chain.ThenFunc(FinishLoginWithCode))
	mux.Handle("/api/pub/register_start", chain.ThenFunc(BeginRegistration))
	mux.Handle("/api/pub/register_finish", chain.ThenFunc(FinishRegistration))
	mux.Handle("/api/pub/login_start", chain.ThenFunc(BeginLogin))
	mux.Handle("/api/pub/login_finish", chain.ThenFunc(FinishLogin))

	mux.Handle("/api/logout", chain.ThenFunc(Logout))
	mux.Handle("/api/credentials", chain.ThenFunc(GetUserCredentials))
	mux.Handle("/api/private", chain.ThenFunc(Private))
	mux.Handle("/api/me", chain.ThenFunc(Me))

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
