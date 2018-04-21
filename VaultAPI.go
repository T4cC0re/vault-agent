package main

import (
	"bytes"
	"github.com/hashicorp/vault/api"
	"unsafe"
	"encoding/base64"
	"encoding/json"
	"strings"
)

type VaultAPI struct {
	client *api.Client
}

type SignatureRequest struct {
	SignatureAlgorithm string `json:"signature_algorithm"`
	Base64Data         string `json:"input""`
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

func ByteToString (byte *[]byte) *string {
	// Fool the typesystem to treat *[]byte as *string
	return (*string)(unsafe.Pointer(byte))
}

func StringToByte (string *string) *[]byte {
	// Fool the typesystem to treat *string as *[]byte
	return (*[]byte)(unsafe.Pointer(string))
}

func (this *VaultAPI) Sign(keyname string, data []byte) ([]byte, error) {
	hashAlgo := "sha2-256"
	sigAlgo := "pss"

	r := this.client.NewRequest("POST", "vault-agent/sign/"+keyname+"/"+hashAlgo)

	inputBase64 := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(inputBase64, data)
	sigReq := &SignatureRequest{SignatureAlgorithm: sigAlgo, Base64Data:*ByteToString(&inputBase64)}

	r.SetJSONBody(sigReq)
	resp, _ := this.client.RawRequest(r)
	defer resp.Body.Close()

	buffer := new(bytes.Buffer)
	buffer.ReadFrom(resp.Body)
	buffBytes := buffer.Bytes()

	var sigResp SignatureResponse
	json.Unmarshal(buffBytes, sigResp)

	whoop := strings.Split(sigResp.Data.Signature, ":")
	output := *StringToByte(&(whoop[2]))
	signature := make([]byte, base64.StdEncoding.DecodedLen(len(output)))
	base64.StdEncoding.Decode(signature, output)

	return signature, nil
}
