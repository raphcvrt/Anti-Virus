package main

import (
	"bytes"
	"encoding/json"
	"net/http"
)

const DiscordWebhookURL = "https://discord.com/api/webhooks/1351146832650305628/sqdAh6ZgA4TR-68aaWI5IVBt_ckpUYwb7rI3pF7O6GQxasHKMzl51yiYCw7wsdwWLQmt"

func sendDiscordAlert(message string) error {
	payload := map[string]string{
		"content": message,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = http.Post(DiscordWebhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	return err
}
