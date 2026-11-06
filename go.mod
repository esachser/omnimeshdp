module github.com/esachser/omnimeshdp

go 1.27.3

require (
	github.com/Microsoft/go-winio v0.6.4
	github.com/esachser/omnimeshcontrol v0.0.0
	github.com/fsnotify/fsnotify v1.10.1
	github.com/spiffe/go-spiffe/v2 v2.9.0
	github.com/spiffe/spire-api-sdk v1.16.0
	golang.org/x/net v0.62.0
	golang.org/x/sys v0.49.0
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/go-jose/go-jose/v4 v4.1.9 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261104224025-d1e00e9f33ab // indirect
)

replace github.com/esachser/omnimeshcontrol => ../omnimeshcontrol
