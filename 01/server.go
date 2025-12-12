package main

import (
	"fmt"
	"net"
)

func main() {
	ln, err := net.Listen("tcp", ":12345")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	fmt.Println("TCP server listening on port 12345")

	conn, err := ln.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s", string(buf[:n]))
	}

}
