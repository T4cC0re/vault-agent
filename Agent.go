package main

import (
	"fmt"
	"errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var E_UNSUPPORTED = errors.New("unsupported action")
var E_NOT_IMPLEMENTED = errors.New("not implemented, yet/work in progress")

type Agent struct {
	vaultToken string
	keys []*agent.Key
	api VaultAPI
}

func newAgent(vaultAddr string, vaultToken string) (Agent, error) {
	api := NewVaultAPI(vaultAddr, vaultToken)

	ag := Agent{vaultToken:vaultToken, api: *api}

	return ag, nil
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
	fmt.Println("Signature requested:", key)

	blob, err := this.api.Sign("ssh-agent", 512, data)
	if err != nil {
		fmt.Sprintf("Error: %v", err)
		return nil, err
	}

	fmt.Printf("Signature:\n - Length .: %d\n - Content : %x\n", len(blob), blob)

	sig := ssh.Signature{Blob:blob,Format:"rsa-sha2-512"}

	return &sig, nil
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
	fmt.Println("RemoveAll")
	return E_UNSUPPORTED
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (this *Agent) Lock(passphrase []byte) error {
	fmt.Println("Lock", passphrase)
	return E_NOT_IMPLEMENTED
}

// Unlock undoes the effect of Lock
func (this *Agent) Unlock(passphrase []byte) error {
	fmt.Println("Unlock", passphrase)
	return E_NOT_IMPLEMENTED
}

// Signers returns signers for all the known keys.
func (this *Agent) Signers() ([]ssh.Signer, error) {
	fmt.Println("Signers")
	return []ssh.Signer{}, E_UNSUPPORTED
}
