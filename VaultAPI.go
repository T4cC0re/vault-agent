package main

import (
	"bytes"
	"github.com/hashicorp/vault/api"
	"encoding/base64"
	"encoding/json"
	"strings"
	"fmt"
)

type VaultAPI struct {
	client *api.Client
}

type SignatureRequest struct {
	SignatureAlgorithm string `json:"signature_algorithm"`
	Base64Data         string `json:"input"`
}
type SignatureResponse struct {
	Data struct{
		Signature string `json:"signature"`
	} `json:"data"`
}

func NewVaultAPI(baseURL string, token string) *VaultAPI {
	client, _ := api.NewClient(api.DefaultConfig())
	client.SetAddress(baseURL)
	client.SetToken(token)
	return &VaultAPI{client: client}
}

func (this *VaultAPI) Sign(keyname string, hashBits uint16, data []byte) ([]byte, error) {
	hashAlgo := fmt.Sprintf("sha2-%d", hashBits)
	sigAlgo := "pkcs1v15"

	r := this.client.NewRequest("POST", "/v1/vault-agent/sign/"+keyname+"/"+hashAlgo)

	inputBase64 := base64.StdEncoding.EncodeToString(data)
	sigReq := &SignatureRequest{SignatureAlgorithm: sigAlgo, Base64Data:inputBase64}

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
