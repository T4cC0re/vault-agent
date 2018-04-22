package main

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"regexp"
	"golang.org/x/crypto/ed25519"
	"encoding/base64"
)

var E_UNSUPPORTED = errors.New("unsupported action")
var E_LOCKED = errors.New("agent locked")

type Agent struct {
	vaultToken string
	keyRegex   *regexp.Regexp
	keys       []*agent.Key
	api        VaultAPI
	locked     bool
	lockHash   []byte
}

func newAgent(vaultAddr string, vaultToken string, endpoint string) (*Agent, error) {
	api := NewVaultAPI(vaultAddr, vaultToken, endpoint)

	//regex, err := regexp.Compile("(?i)^ssh-ed25519.*$")
	regex, err := regexp.Compile("(?i)^ssh-.*$")
	if err != nil {
		return nil, err
	}

	ag := &Agent{vaultToken: vaultToken, api: *api, keyRegex: regex}

	// Fetch keys beforehand
	_, err = ag.List()
	if err != nil {
		return nil, err
	}

	return ag, nil
}

// List returns the identities known to the agent.
func (this *Agent) List() ([]*agent.Key, error) {
	log.Println("List")
	if this.locked {
		return nil, E_LOCKED
	}

	if len(this.keys) == 0 {
		keys, err := this.api.FetchKeys(this.keyRegex)
		if err != nil {
			return nil, err
		}
		this.keys = keys

		log.Printf("%x %d", keys[0].Blob, len(keys[0].Blob))
	}

	return this.keys, nil

}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (this *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	log.Println("Signature requested:", key)
	if this.locked {
		return nil, E_LOCKED
	}

	log.Println("Sign type:", key.Type(), len(data))

	var sigAlgo string
	switch key.Type() {
	case "ssh-ed25519":
		sigAlgo = "" // Omit sending a signature_altorithm field
	default:
		sigAlgo = "pkcs1v15"
	}
	blob, err := this.api.Sign("ssh-agent", 512, data, sigAlgo)
	if err != nil {
		fmt.Sprintf("Error: %v", err)
		return nil, err
	}

	log.Printf("Signature:\n - Length .: %d\n - Content : %x\n", len(blob), blob)

	var format string
	switch key.Type() {
	case "ssh-ed25519":
		format = "ssh-ed25519"

public:= "SdGYAbba5QpYy01DI+zePt76ww2phVs7SQSjMGtCJvo="
		keyBlob, err := base64.StdEncoding.DecodeString(public)

		log.Println("Len", len(public), len(keyBlob))
		if err != nil {
			log.Println(err)
		}

		ok := ed25519.Verify(keyBlob, data, blob)
		fmt.Printf("SigOK?: %v\n", ok) /// => false
		/// TODO: Find out why this fails

	default:
		format = "rsa-sha2-512"
	}

	sig := ssh.Signature{Blob: blob, Format: format}

	return &sig, nil
}

// Add adds a private key to the agent.
func (this *Agent) Add(key agent.AddedKey) error {
	log.Println("Add", key)
	return E_UNSUPPORTED
}

// Remove removes all identities with the given public key.
func (this *Agent) Remove(key ssh.PublicKey) error {
	log.Println("Remove", key)
	return E_UNSUPPORTED

}

// RemoveAll removes all identities.
func (this *Agent) RemoveAll() error {
	log.Println("RemoveAll called. Destroying cached public-keys")
	this.keys = []*agent.Key{}
	return nil
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (this *Agent) Lock(passphrase []byte) error {
	log.Println("Locking agent and destroying cached public-keys", passphrase)
	if this.locked {
		return E_LOCKED
	}

	lockHash, err := bcrypt.GenerateFromPassword(passphrase, 10)
	if err != nil {
		return err
	}

	this.lockHash = lockHash
	this.locked = true
	this.keys = []*agent.Key{}
	return nil
}

// Unlock undoes the effect of Lock
func (this *Agent) Unlock(passphrase []byte) error {
	log.Println("Unlocking agent and re-fetch available keys", passphrase)
	if err := bcrypt.CompareHashAndPassword(this.lockHash, passphrase); err != nil {
		return err
	}

	this.locked = false

	if len(this.keys) == 0 {
		keys, err := this.api.FetchKeys(this.keyRegex)
		if err != nil {
			return err
		}
		this.keys = keys
	}

	return nil
}

// Signers returns signers for all the known keys.
func (this *Agent) Signers() ([]ssh.Signer, error) {
	log.Println("Signers")
	return []ssh.Signer{}, E_UNSUPPORTED
}
