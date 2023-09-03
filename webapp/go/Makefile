isuports: test go.mod go.sum *.go cmd/isuports/*
	go build -o isuports ./cmd/isuports

test:
	go test -v ./...

deploy:
	sudo systemctl restart isuports.service

show-applog:
	sudo journalctl -u isuports.service
