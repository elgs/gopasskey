package main

import (
	"fmt"
	"net/smtp"
	"os"
	"strings"
)

// getEnv is a helper function to get the environment variable
func getEnv(key, def string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return def
}

func SendMail(to, subject, body string) error {
	from := getEnv("SMTP_USER", "")
	password := getEnv("SMTP_PASS", "")
	smtpHost := getEnv("SMTP_HOST", "")
	smtpPort := getEnv("SMTP_PORT", "")

	toArray := strings.Split(to, ",")

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: " + subject + "\n\n" +
		body

	auth := smtp.PlainAuth("", from, password, smtpHost)
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, toArray, []byte(msg))
	if err != nil {
		return fmt.Errorf("failed to send mail: %w", err)
	}
	return nil
}
