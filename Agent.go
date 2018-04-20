package main

import (
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Agent struct {
}

func newAgent(sockPath string) error {
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
	return []*agent.Key{}, nil
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (this *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	fmt.Println("Sign", key, data)
	return nil, nil
}

// Add adds a private key to the agent.
func (this *Agent) Add(key agent.AddedKey) error {
	fmt.Println("Add", key)
	return nil
}

// Remove removes all identities with the given public key.
func (this *Agent) Remove(key ssh.PublicKey) error {
	fmt.Println("Remove", key)
	return nil

}

// RemoveAll removes all identities.
func (this *Agent) RemoveAll() error {
	fmt.Println("Removeall")
	return nil
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (this *Agent) Lock(passphrase []byte) error {
	fmt.Println("lock", passphrase)
	return nil
}

// Unlock undoes the effect of Lock
func (this *Agent) Unlock(passphrase []byte) error {
	fmt.Println("unlock", passphrase)
	return nil
}

// Signers returns signers for all the known keys.
func (this *Agent) Signers() ([]ssh.Signer, error) {
	fmt.Println("signers")
	return []ssh.Signer{}, nil
}
