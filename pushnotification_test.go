package pushnotification

import (
	"log"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
)

func TestSend(t *testing.T) {
	assert := assert.New(t)

	svc := Service{
		Key:    os.Getenv("KEY"),
		Secret: os.Getenv("SECRET"),
		Region: os.Getenv("REGION"),
		// provide at least one of these, based on the devicetype
		APNS:        os.Getenv("APNS"),
		APNSSandbox: os.Getenv("APNSSandbox"),
		GCM:         os.Getenv("GCM"),
		Windows:     os.Getenv("WINDOWS"),
		Platforms: map[string]string{
			"baidu": os.Getenv("baidu"),
		},
	}

	device := &Device{
		Token:       os.Getenv("DEVICE_TOKEN"),
		Type:        os.Getenv("DEVICE_TYPE"),
		EndpointArn: os.Getenv("DEVICE_ENDPOINT_ARN"), //optional
	}

	err := svc.Send(device, &Data{
		Subject: aws.String("Subject"),
		Alert:   aws.String("Nice test message"),
		Sound:   aws.String("default"),
		Badge:   aws.Int(1),
		Data: map[string]interface{}{
			"entity": "57cd5acb3b983b0b00bdabf7",
			"topic":  "Nice topic",
			"data": map[string]interface{}{
				"evenmore": "568cef4ca041160a00911dd6",
			},
		},
	})

	assert.NoError(err)
	assert.NotEqual("", device.EndpointArn, "Device endpoint Arn should be populated")

	if device.IsCreated() {
		log.Printf("New endpoint arn '%v' created for device token '%v'", device.EndpointArn, device.Token)
	}
}
