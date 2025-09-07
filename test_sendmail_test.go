package main

import "testing"

func TestSendMail(t *testing.T) {
	to := "qc@az.ht, i@az.ht"
	subject := "Test Subject"
	body := "This is a test email."

	err := SendMail(to, subject, body)
	if err != nil {
		t.Errorf("SendMail failed: %v", err)
	}
}
