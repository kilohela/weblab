all: client server

client: client.c
	gcc client.c -o client -g

server: server.c
	gcc server.c -o server -g

run: client server
	./server &
	sleep 1
	./client

trace: client server
	strace -o server.log ./server &
	sleep 1
	strace -o client.log ./client

clean:
	rm -f client client.log server server.log

go: goc gos

goc: client.go
	go build -o $@ $^

gos: server.go
	go build -o $@ $^

go-run: goc gos
	./gos &
	sleep 1
	./goc

go-trace: goc gos
	strace -o gos.log ./gos &
	sleep 1
	strace -o goc.log ./goc

clean-go:
	rm -f goc gos goc.log gos.log

clean-all: clean clean-go
