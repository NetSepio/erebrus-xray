package http

import (
	"encoding/hex"
	"aidanwoods.dev/go-paseto"
	"github.com/xtls/xray-core/common/errors" // no alias
)

// getDecodedPasetoPublicKey decodes the hex public key string and returns a PASETO V4 public key
func getDecodedPasetoPublicKey(pubKey string) (paseto.V4AsymmetricPublicKey, error) {
	errors.LogInfo(nil, "Paseto original public key (hex): ", pubKey)

	keyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		errors.LogWarning(nil, "Invalid hex PASETO public key: ", err.Error())
		return paseto.V4AsymmetricPublicKey{}, errors.New("invalid hex PASETO public key: " + err.Error())
	}
	errors.LogInfo(nil, "Paseto decoded public key (bytes): ", keyBytes)

	pk, err := paseto.NewV4AsymmetricPublicKeyFromBytes(keyBytes)
	if err != nil {
		errors.LogWarning(nil, "Failed to parse PASETO public key: ", err.Error())
		return paseto.V4AsymmetricPublicKey{}, errors.New("failed to parse PASETO public key: " + err.Error())
	}
	return pk, nil
}

// VerifyPasetoToken verifies v4.public token signature and expiration
func VerifyPasetoToken(pubKey string, tokenStr string) error {
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())

	pasetoPublicKey, err := getDecodedPasetoPublicKey(pubKey)
	if err != nil {
		return errors.New("failed to decode PASETO public key: " + err.Error())
	}

	_, err = parser.ParseV4Public(pasetoPublicKey, tokenStr, nil)
	if err != nil {
		errors.LogWarning(nil, "Received PASETO token: ", tokenStr)
		errors.LogWarning(nil, "Invalid or expired PASETO token: ", err.Error())
		return errors.New("invalid or expired PASETO token: " + err.Error())
	}
	return nil
}
