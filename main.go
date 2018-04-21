package main

import (
	"fmt"
	"os"
)

func main() {
	agent := newAgent("/tmp/vault-agent.sock", os.Getenv("VAULT_TOKEN"))
	fmt.Printf("Hello, world.\n%v", agent)
}
