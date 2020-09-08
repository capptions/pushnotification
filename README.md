pushnotification
===
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Package `pushnotification` sends push notification via Amazon SNS based on the device token.
Provide the type of the device and optional the EndpointArn. The EndpointArn will be created on the fly if needed. This can be stored afterwards for future use.
Device types `ios`, `android` and `windows` are supported by default, for other platforms you need to provide the device type.
If `APNSSandbox` is provided and the type is `ios`, a pushnotofication will be sent to both `APNS` and `APNSSandbox`, the endpoint for `APNS` will be populated.
When you need the endpoint for `APNSSandbox`, don't provide `APNSSandbox` but a custom type in `platforms` and provide a custom `type` for the device.

## Example

```go
package main

import (
	"log"
	"os"

	"github.com/capptions/pushnotification"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal(err)
	}

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

	device := &pushnotification.Device{
		Token:       os.Getenv("DEVICE_TOKEN"),
		Type:        os.Getenv("DEVICE_TYPE"), //'ios|android|windows|custom'
		EndpointArn: os.Getenv("DEVICE_ENDPOINT_ARN"), //optional
	}

	err := svc.Send(device, &pushnotification.Data{
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
	if err != nil {
		log.Fatal(err)
	}
}
```

```bash
KEY=your_key SECRET=your_secret REGION=eu-west-1 APNS=app_ARN DEVICE_TOKEN=device_token DEVICE_TYPE=ios go test
```

## Setup SNS stuff on Amazon
### Amazon SNS
Create platform application for each supported device type in Amazon SNS and remember the application ARN.

### Amazon IAM
Create a user and add this policy. The 'resources' should list the application ARNs you created.
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1472041226000",
            "Effect": "Allow",
            "Action": [
                "sns:Publish",
                "sns:CreatePlatformEndpoint",
                "sns:GetEndpointAttributes",
                "sns:SetEndpointAttributes"
            ],
            "Resource": [
                "iOS",
                "Android"
            ]
        }
    ]
}
```

### Devices
The endpoints for the device tokens will be added on the fly, you can however store the EndpointArn for reuse.
The endpoint will be stored in the Device struct. If the provided endpoint is empty, it will be created, otherwise it will be reused when possible.
Function 'IsCreated' will return if the endpoint is (re)created or not.

```go
device := &pushnotification.Device{
	Token:       os.Getenv("DEVICE_TOKEN"),
	Type:        os.Getenv("DEVICE_TYPE"), //'ios|android|windows|custom'
	EndpointArn: os.Getenv("DEVICE_ENDPOINT_ARN"), //optional
}

if device.IsCreated() {
	log.Printf("New endpoint arn '%v' created for device token '%v'", device.EndpointArn, device.Token)
}
```

## License

pushnotification is released under the MIT License.
