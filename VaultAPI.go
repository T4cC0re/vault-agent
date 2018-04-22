package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"regexp"
	"strconv"
	"strings"
	"golang.org/x/crypto/ed25519"
)

type VaultAPI struct {
	client   *api.Client
	endpoint string
}

type SignatureRequest struct {
	SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	Base64Data         string `json:"input"`
}
type SignatureResponse struct {
	Data struct {
		Signature string `json:"signature"`
	} `json:"data"`
}
type ListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}
type KeyObject struct {
	PublicKey string `json:"public_key"`
	Creation  string `json:"creation_time"`
}

type KeyResponse struct {
	Data struct {
		Keys          map[string]KeyObject `json:"keys"`
		LatestVersion int                  `json:"latest_version"`
		Type          string               `json:"type"`
	} `json:"data"`
}

func NewVaultAPI(baseURL string, token string, endpoint string) *VaultAPI {
	client, _ := api.NewClient(api.DefaultConfig())
	client.SetAddress(baseURL)
	client.SetToken(token)
	return &VaultAPI{client: client, endpoint: endpoint}
}

var (
	E_PEM_INVALID      = errors.New("PEM formatted incorrectly")
	E_UNSUPPORTED_TYPE = errors.New("PEM type unsupported")
)

// Converts public keys to SSH wire format
func publicKeyToBlob(keyInput []byte, keyType string) ([]byte, error) {
	var pub ssh.PublicKey

	switch keyType {
	case "rsa-2048", "rsa-4096":
		der, rest := pem.Decode(keyInput)
		if der == nil {
			return nil, E_PEM_INVALID
		}
		if len(rest) > 0 {
			// More than just a public key
			return nil, E_PEM_INVALID
		}

		if der.Type != "PUBLIC KEY" {
			return nil, E_UNSUPPORTED_TYPE
		}

		pubKeyPointer, err := x509.ParsePKIXPublicKey(der.Bytes)
		if err != nil {
			return nil, err
		}
		pub, err := ssh.NewPublicKey(pubKeyPointer)
		if err != nil {
			return nil, err
		}
		return pub.Marshal(), nil
	case "ed25519":
		ed25519Bytes, err := base64.StdEncoding.DecodeString(string(keyInput))
		pubKey := ed25519.PublicKey(ed25519Bytes)
		pub, err = ssh.NewPublicKey(pubKey)
		if err != nil {
			return nil, err
		}
		if len(ed25519Bytes) != ed25519.PublicKeySize {
			return nil, E_PEM_INVALID
		}
	default:
		log.Println("Unsupported type", keyType)
		return nil, E_PEM_INVALID
	}
	return pub.Marshal(), nil

}

func (this *VaultAPI) Sign(keyname string, hashBits uint16, data []byte, sigAlgo string) ([]byte, error) {
	hashAlgo := fmt.Sprintf("sha2-%d", hashBits)
	r := this.client.NewRequest("POST", "/v1"+this.endpoint+"/sign/"+keyname+"/"+hashAlgo)

	inputBase64 := base64.StdEncoding.EncodeToString(data)
	sigReq := &SignatureRequest{SignatureAlgorithm: sigAlgo, Base64Data: inputBase64}

	r.SetJSONBody(sigReq)
	resp, err := this.client.RawRequest(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buffer := new(bytes.Buffer)
	buffer.ReadFrom(resp.Body)
	buffBytes := buffer.Bytes()

	var sigResp SignatureResponse

	json.Unmarshal(buffBytes, &sigResp)

	whoop := strings.Split(sigResp.Data.Signature, ":")
	signature, err := base64.StdEncoding.DecodeString(whoop[2])

	return signature, nil
}

func (this *VaultAPI) fetchKey(name string) (*agent.Key, error) {
	log.Println("Get key", name)

	var keyResp KeyResponse
	// region Request
	r := this.client.NewRequest("GET", "/v1"+this.endpoint+"//keys/"+name)
	resp, err := this.client.RawRequest(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buffer := new(bytes.Buffer)
	buffer.ReadFrom(resp.Body)
	buffBytes := buffer.Bytes()

	log.Println(string(buffBytes))

	json.Unmarshal(buffBytes, &keyResp)
	// endregion

	log.Println(keyResp.Data.LatestVersion)
	log.Println(keyResp.Data.Type)
	key := keyResp.Data.Keys[strconv.FormatInt(int64(keyResp.Data.LatestVersion), 10)]

	blob, err := publicKeyToBlob([]byte(key.PublicKey), keyResp.Data.Type)
	if err != nil {
		return nil, err
	}

	return &agent.Key{Comment: fmt.Sprintf("Vault key '%s' (%s created at %s)", name, keyResp.Data.Type, strings.SplitN(key.Creation, ".", 2)[0]), Format: "ssh-rsa", Blob: blob}, nil
}

func (this *VaultAPI) FetchKeys(regex *regexp.Regexp) ([]*agent.Key, error) {
	log.Printf("Fetching keys matching '%s'...\n", regex.String())

	var listResp ListResponse
	// region Request
	r := this.client.NewRequest("LIST", "/v1"+this.endpoint+"//keys")
	resp, err := this.client.RawRequest(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buffer := new(bytes.Buffer)
	buffer.ReadFrom(resp.Body)
	buffBytes := buffer.Bytes()

	log.Println(string(buffBytes))

	json.Unmarshal(buffBytes, &listResp)
	// endregion

	keys := make([]*agent.Key, 0)

	for _, keyName := range listResp.Data.Keys {
		log.Println("Iterate", keyName, regex.MatchString(keyName))
		if !regex.MatchString(keyName) {
			continue
		}

		key, err := this.fetchKey(keyName)
		if err != nil {
			log.Println(err)
		}
		keys = append(keys, key)
	}

	return keys, nil
}
