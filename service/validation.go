package service

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// ValidateMessage checks if the message is non-empty.
func ValidateMessage(message string) error {
	if len(message) == 0 {
		return errors.New("message cannot be empty")
	}
	return nil
}

// ValidateSignature checks if the signature is non-empty.
func ValidateSignature(signature string) error {
	if len(signature) == 0 {
		return errors.New("signature cannot be empty")
	}
	return nil
}

// ValidatePrivateKey checks if the private key is a valid RSA key.
func ValidatePrivateKey(privateKey string) error {
	// 解析出一个 pem.Block 数据结构
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return errors.New("invalid RSA private key")
	}
	// 解析出一个 RSA 私钥
	_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return errors.New("unable to parse private key")
	}
	return nil
}

// ValidatePublicKey checks if the public key is a valid RSA key.
func ValidatePublicKey(publicKey string) error {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return errors.New("invalid RSA public key")
	}
	_, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.New("unable to parse public key")
	}
	return nil
}
