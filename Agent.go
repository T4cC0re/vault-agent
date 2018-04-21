package main

import (
	"fmt"
	"net"

	"errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"os"
)

var E_UNSUPPORTED = errors.New("unsupported action")
var E_NOT_IMPLEMENTED = errors.New("not implemented, yet/work in progress")

type Agent struct {
	vaultToken string
	keys []*agent.Key
}

func newAgent(sockPath string, vaultToken string) error {

	fmt.Fprintf(os.Stderr, "Starting agent at '%s' with token '%s'\n", sockPath, vaultToken)

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}

	ag := Agent{}

	for {
		conn, err := l.Accept()
		if err != nil {
			// handle error
			continue
		}
		agent.ServeAgent(&ag, conn)
	}

	return nil
}

// List returns the identities known to the agent.
func (this *Agent) List() ([]*agent.Key, error) {
	fmt.Println("List")

	if len(this.keys) == 0 {
	  keys, err := fetchKeys("", this.vaultToken)
	  if err != nil {
	  	return nil, err
	  }
	  this.keys = keys
	}

	return this.keys, nil

}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (this *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	fmt.Println("Sign", key, data)
	return nil, E_NOT_IMPLEMENTED
}

// Add adds a private key to the agent.
func (this *Agent) Add(key agent.AddedKey) error {
	fmt.Println("Add", key)
	return E_UNSUPPORTED
}

// Remove removes all identities with the given public key.
func (this *Agent) Remove(key ssh.PublicKey) error {
	fmt.Println("Remove", key)
	return E_UNSUPPORTED

}

// RemoveAll removes all identities.
func (this *Agent) RemoveAll() error {
	fmt.Println("Removeall")
	return E_UNSUPPORTED
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (this *Agent) Lock(passphrase []byte) error {
	fmt.Println("lock", passphrase)
	return E_NOT_IMPLEMENTED
}

// Unlock undoes the effect of Lock
func (this *Agent) Unlock(passphrase []byte) error {
	fmt.Println("unlock", passphrase)
	return E_NOT_IMPLEMENTED
}

// Signers returns signers for all the known keys.
func (this *Agent) Signers() ([]ssh.Signer, error) {
	fmt.Println("signers")
	return []ssh.Signer{}, E_UNSUPPORTED
}
