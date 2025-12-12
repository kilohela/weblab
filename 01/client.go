package main

import (
	"bufio"
	"net"
	"os"
)

func main() {
	serverIP := os.Getenv("SERVER_IP")
	conn, err := net.Dial("tcp", serverIP+":12345")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	msg := "Hello, TCP server!\n"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		panic(err)
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		text, err := reader.ReadString('\n')
		_, err = conn.Write([]byte(text))
		if err != nil {
			panic(err)
		}
	}
}
