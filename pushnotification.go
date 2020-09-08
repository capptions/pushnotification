package pushnotification

import (
	"errors"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sns"
)

// Service is the main entry point into using this package.
type Service struct {
	Key         string
	Secret      string
	Region      string
	GCM         string
	APNS        string
	APNSSandbox string
	Windows     string
	Platforms   map[string]string
}

type Device struct {
	Token       string
	Type        string
	EndpointArn string
	created     bool
}

func (device *Device) IsCreated() bool {
	return device.created
}

// Data is the data of the sending pushnotification.
type Data struct {
	Alert           *string                `json:"alert,omitempty"`
	Subject         *string                `json:"subject,omitempty"`
	Sound           *string                `json:"sound,omitempty"`
	Badge           *int                   `json:"badge,omitempty"`
	Data            map[string]interface{} `json:"custom_data"`
}

// Send sends a push notification
func (service *Service) Send(device *Device, data *Data) (err error) {
	svc := sns.New(session.New(&aws.Config{
		Credentials: credentials.NewStaticCredentials(service.Key, service.Secret, ""),
		Region:      aws.String(service.Region),
	}))

	message, err := newMessageJSON(data)
	if err != nil {
		log.Println("Message could not be created", err)
		return
	}
	err = service.pushToDevice(svc, device, *data.Subject, message)

	// or get this extra info from an app
	if device.Type == "ios" && len(service.APNSSandbox) > 0 {
		sandBox := &Device{
			Token: device.Token,
			Type:  "_ios_sandbox_",
		}
		err = service.pushToDevice(svc, sandBox, *data.Subject, message)
	}

	return
}

func (service *Service) pushToDevice(svc *sns.SNS, device *Device, subject string, message string) (err error) {
	err = service.getEndpointArn(svc, device)
	if err != nil {
		log.Println("Endpoint could not be retrieved", err)
		return
	}

	input := &sns.PublishInput{
		Message:          aws.String(message),
		MessageStructure: aws.String("json"),
		TargetArn:        aws.String(device.EndpointArn),
	}

	if subject != "" {
		input.Subject = aws.String(subject)
	}
	_, err = svc.Publish(input)
	return
}

// get platform ARN for device, create or update when needed
func (service *Service) getEndpointArn(svc *sns.SNS, device *Device) (err error) {
	// recommended approach with endpointArn
	// https://mobile.awsblog.com/post/Tx223MJB0XKV9RU/Mobile-token-management-with-Amazon-SNS

	if len(device.EndpointArn) == 0 {
		device.EndpointArn, err = service.createEndpointArn(svc, device)
		if err != nil {
			return
		}
		device.created = true
	}

	// get endpoint and check status etc
	resp, err := svc.GetEndpointAttributes(&sns.GetEndpointAttributesInput{
		EndpointArn: aws.String(device.EndpointArn),
	})
	if err != nil {
		// endpoint is not there
		device.EndpointArn, err = service.createEndpointArn(svc, device)
		if err != nil {
			return
		}
		device.created = true
	} else if *resp.Attributes["Token"] == device.Token || *resp.Attributes["Enabled"] != "true" {
		// update endpoint
		params := &sns.SetEndpointAttributesInput{
			Attributes: map[string]*string{
				"Token":   aws.String(device.Token),
				"Enabled": aws.String("true"),
			},
			EndpointArn: aws.String(device.EndpointArn),
		}
		_, err := svc.SetEndpointAttributes(params)
		if err != nil {
			log.Println("Endpoint could not be updated", err)
		}
	}

	return
}

// create platform ARN for device
func (service *Service) createEndpointArn(svc *sns.SNS, device *Device) (string, error) {
	platform, err := service.getPlatform(device)
	if err != nil {
		log.Println(err)
		return "", err
	}

	resp, err := svc.CreatePlatformEndpoint(&sns.CreatePlatformEndpointInput{
		PlatformApplicationArn: aws.String(platform),
		Token: aws.String(device.Token),
	})

	if err != nil {
		log.Println(err)
		return "", err
	}
	return *resp.EndpointArn, err
}

// get application ARN for device type
func (service *Service) getPlatform(device *Device) (platform string, err error) {
	deviceType := strings.ToLower(device.Type)
	if deviceType == "gcm" && len(service.GCM) > 0 {
		platform = service.GCM
	} else if deviceType == "android" && len(service.GCM) > 0 {
		platform = service.GCM
	} else if deviceType == "ios" && len(service.APNS) > 0 {
		platform = service.APNS
	} else if deviceType == "_ios_sandbox_" && len(service.APNSSandbox) > 0 {
		platform = service.APNSSandbox
	} else if deviceType == "windows" && len(service.Windows) > 0 {
		platform = service.Windows
	} else {
		notfound := true
		if service.Platforms != nil {
			if value, ok := service.Platforms[deviceType]; ok {
				platform = value
				notfound = false
			}
		}
		if notfound {
			err = errors.New("Device.Type " + device.Type + " not supported")
		}
	}
	return
}
