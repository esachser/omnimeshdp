module github.com/esachser/omnimeshdp

go 1.27.3

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/esachser/omnimeshcontrol v0.0.0
	github.com/fsnotify/fsnotify v1.10.1
	github.com/spiffe/go-spiffe/v2 v2.8.1
	github.com/spiffe/spire-api-sdk v1.15.3
	golang.org/x/net v0.51.0
	golang.org/x/sys v0.42.0
	google.golang.org/grpc v1.79.3
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)

replace github.com/esachser/omnimeshcontrol => ../omnimeshcontrol
