package main

import "fmt"

func main() {
	agent := newAgent("/tmp/vault-agent.sock")
	fmt.Printf("Hello, world.\n%v", agent)
}
