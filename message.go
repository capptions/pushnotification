package pushnotification

import "encoding/json"

type message struct {
	APNS        string `json:"APNS"`
	APNSSandbox string `json:"APNS_SANDBOX"`
	Default     string `json:"default"`
	GCM         string `json:"GCM"`
}

func newMessageJSON(data *Data) (m string, err error) {
	b, err := json.Marshal(map[string]interface{}{
		"aps": enrich(map[string]interface{}{
			"alert": map[string]interface{}{
				"body":  data.Alert,
				"title": data.Subject,
			},
			"sound":             data.Sound,
			"badge":             data.Badge,
			"content-available": 1,
		}, data.Data),
	})
	if err != nil {
		return
	}
	payload := string(b)

	// GCM/FCM requires notification object for display, and separate data object for custom data
	gcmPayload := map[string]interface{}{
		"priority": "high",
		"notification": map[string]interface{}{
			"title": data.Subject,
			"body":  data.Alert,
		},
		"data": data.Data, // Only custom data goes here, not title/message/badge
	}

	b, err = json.Marshal(gcmPayload)
	if err != nil {
		return
	}
	gcm := string(b)

	pushData, err := json.Marshal(message{
		Default:     *data.Alert,
		APNS:        payload,
		APNSSandbox: payload,
		GCM:         gcm,
	})
	if err != nil {
		return
	}
	m = string(pushData)
	return
}

func enrich(message map[string]interface{}, custom map[string]interface{}) map[string]interface{} {
	for key, value := range custom {
		message[key] = value
	}
	return message
}
