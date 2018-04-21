package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Converts PEM public key to OpenSSH format to be used in authorized_keys file
// Similar to: "ssh-keygen", "-i", "-m", "pkcs8", "-f", auth_keys_new_path
func publicPEMtoBlob(pemBytes []byte) ([]byte, error) {
	// Decode and get the first block in the PEM file.
	// In our case it should be the Public key block.
	pemBlock, rest := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("invalid PEM public key passed, pem.Decode() did not find a public key")
	}
	if len(rest) > 0 {
		return nil, errors.New("PEM block contains more than just public key")
	}

	// Confirm we got the PUBLIC KEY block type
	if pemBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("ssh: unsupported key type %q", pemBlock.Type)
	}

	// Convert to rsa
	rsaPubKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, err //  "x509.parse pki public key")
	}

	// Confirm we got an rsa public key. Returned value is an interface{}
	sshKey, ok := rsaPubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid PEM passed in from user")
	}

	// Generate the ssh public key
	pub, err := ssh.NewPublicKey(sshKey)
	if err != nil {
		return nil, err // "new ssh public key from pem converted to rsa")
	}

	return pub.Marshal(), nil
}

func fetchKeys (baseUrl string, token string) ([]*agent.Key, error) {
	fmt.Println("Fetching keys")

	keys := make([]*agent.Key, 1)

	p := []byte("-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA02XhXVnLbW9FNZKzEwJ4\nQen+hOhYmY73+iUkH1H4gyrrlhsHAaIWFkxcqy/vfEn6NB8iZh1owoJwrP46/I/E\ngQAmpEZ0D8E6hNnl2VjUK0N26xRNsGqUX/hnntXect3WX3f5VhSBWgFEiBCoRIjN\nLV+99X07ZFMtRIDLnLpc0jw/48R3hMKCqrXtuL/UDEzVp/AX3CANZjUg3APu98h+\n53Nk6qBYoLXzO2SjporKKqDFOncc2oFDgkrovGoPBq+wc6zWF7DOyGOCCMNYu7aI\nVyF1xpHxqxIJWmDYOw76GDxRE2niVjx9zCelXpJOue4Jd9L7YZ2N1yxzCllHY70Q\nY62q2cM76j2BLB3ziQioCgYgjpaMHW7trpft7uK89oHNX9lTHj8zRQ0seNeul/tI\ngJLqnn0uFpREBI4XJkDu5iq3OTZpZstl5mBNsAMD/e9FvBDJuxyAUWNjlF5pdfeq\nJ93rjzkFphXcwCvmX/B2eEcTd6DusC7E+xQab5GMPdPcMrA+GPobreQ/IQ2VmlYr\nj/WRvDBW+JPp8kQLbe1RNMZnZQT8ejydpgZp66hFXxSqocb0xlAtmUEXazeOaiXg\nBdY7+dRnAjESMeUpBURz3o6mQc5UJD9eXCHIm0Njaqs2QPRTPcMlitQ2AWD+So7K\nCz6mz/xMaHgLRPw9AMJFfPkCAwEAAQ==\n-----END PUBLIC KEY-----\n")

	blob, err := publicPEMtoBlob(p)
	if err != nil {
		return []*agent.Key{}, nil
	}

	keys[0] = &agent.Key{Comment: "ssh-agent;1", Format: "ssh-rsa", Blob: blob}
	return keys, nil
}