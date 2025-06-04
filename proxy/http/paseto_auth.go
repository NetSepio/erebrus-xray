package http

import (
	"encoding/hex"
	"errors"
	"aidanwoods.dev/go-paseto"
)

// getDecodedPasetoPublicKey decodes the hex public key string and returns a PASETO V4 public key
func getDecodedPasetoPublicKey(pubKey string) (paseto.V4AsymmetricPublicKey, error) {
	println("Paseto original public key (hex):", pubKey)

	keyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		println("Invalid hex PASETO public key:", err.Error())
		return paseto.V4AsymmetricPublicKey{}, errors.New("invalid hex PASETO public key: " + err.Error())
	}
	println("Paseto decoded public key (bytes):", keyBytes)

	pk, err := paseto.NewV4AsymmetricPublicKeyFromBytes(keyBytes)
	if err != nil {
		println("Failed to parse PASETO public key:", err.Error())
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
		println("Received paseto token: ", tokenStr)
		println("Invalid or expired PASETO token:", err.Error())
		return errors.New("invalid or expired PASETO token: " + err.Error())
	}
	return nil
}
