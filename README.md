Seperate Transit volume at /vault-agent

Create key via https://vault.t4cc0.re:8200/v1/vault-agent/keys/NAME
Body:
```
{"type": "rsa-4096"}
```

Iterate over keys in store
```
curl -i -X LIST --header "X-Vault-Token: ${VAULT_TOKEN}" 
'https://vault.t4cc0.re:8200/v1/vault-agent/keys'
HTTP/2 200
cache-control: no-store
content-type: application/json
content-length: 180
date: Fri, 20 Apr 2018 22:09:02 GMT

{"request_id":"7c6c3cb1-4cb7-e9d2-0878-d69a44e40abd","lease_id":"","renewable":false,"lease_duration":0,"data":{"keys":["ssh-agent"]},"wrap_info":null,"warnings":null,"auth":null}
```

Query info for key
```
curl -i -X GET --header "X-Vault-Token: ${VAULT_TOKEN}" 
'https://vault.t4cc0.re:8200/v1/vault-agent/keys/ssh-agent'
HTTP/2 200
cache-control: no-store
content-type: application/json
content-length: 1377
date: Fri, 20 Apr 2018 22:12:55 GMT

{"request_id":"8896a785-12b5-f3d3-370d-f0c138569986","lease_id":"","renewable":false,"lease_duration":0,"data":{"allow_plaintext_backup":false,"deletion_allowed":false,"derived":false,"exportable":true,"keys":{"1":{"creation_time":"2018-04-20T22:02:04.290539906Z","name":"rsa-4096","public_key":"-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA02XhXVnLbW9FNZKzEwJ4\nQen+hOhYmY73+iUkH1H4gyrrlhsHAaIWFkxcqy/vfEn6NB8iZh1owoJwrP46/I/E\ngQAmpEZ0D8E6hNnl2VjUK0N26xRNsGqUX/hnntXect3WX3f5VhSBWgFEiBCoRIjN\nLV+99X07ZFMtRIDLnLpc0jw/48R3hMKCqrXtuL/UDEzVp/AX3CANZjUg3APu98h+\n53Nk6qBYoLXzO2SjporKKqDFOncc2oFDgkrovGoPBq+wc6zWF7DOyGOCCMNYu7aI\nVyF1xpHxqxIJWmDYOw76GDxRE2niVjx9zCelXpJOue4Jd9L7YZ2N1yxzCllHY70Q\nY62q2cM76j2BLB3ziQioCgYgjpaMHW7trpft7uK89oHNX9lTHj8zRQ0seNeul/tI\ngJLqnn0uFpREBI4XJkDu5iq3OTZpZstl5mBNsAMD/e9FvBDJuxyAUWNjlF5pdfeq\nJ93rjzkFphXcwCvmX/B2eEcTd6DusC7E+xQab5GMPdPcMrA+GPobreQ/IQ2VmlYr\nj/WRvDBW+JPp8kQLbe1RNMZnZQT8ejydpgZp66hFXxSqocb0xlAtmUEXazeOaiXg\nBdY7+dRnAjESMeUpBURz3o6mQc5UJD9eXCHIm0Njaqs2QPRTPcMlitQ2AWD+So7K\nCz6mz/xMaHgLRPw9AMJFfPkCAwEAAQ==\n-----END PUBLIC KEY-----\n"}},"latest_version":1,"min_decryption_version":1,"min_encryption_version":0,"name":"ssh-agent","supports_decryption":true,"supports_derivation":false,"supports_encryption":true,"supports_signing":true,"type":"rsa-4096"},"wrap_info":null,"warnings":null,"auth":null}
```
Always use latest version!
