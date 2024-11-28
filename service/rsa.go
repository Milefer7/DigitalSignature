package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// Helper to load keys
func loadKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	file, err := os.ReadFile("data/keys.json")
	if err != nil {
		return nil, nil, err
	}

	var keys struct {
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	}

	if err := json.Unmarshal(file, &keys); err != nil {
		return nil, nil, err
	}

	privKeyBlock, _ := pem.Decode([]byte(keys.PrivateKey))
	pubKeyBlock, _ := pem.Decode([]byte(keys.PublicKey))

	privateKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey.(*rsa.PublicKey), nil
}

func GenerateSignature(c *gin.Context) {
	var req struct {
		Message    string `json:"message"`
		PrivateKey string `json:"private_key"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate inputs
	if err := ValidateMessage(req.Message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := ValidatePrivateKey(req.PrivateKey); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	block, _ := pem.Decode([]byte(req.PrivateKey))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse private key"})
		return
	}

	hash := sha512.Sum512([]byte(req.Message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hash[:])
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Signature generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"signature": base64.StdEncoding.EncodeToString(signature)})
}
func VerifySignature(c *gin.Context) {
	var req struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
		PublicKey string `json:"public_key"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate inputs
	if err := ValidateMessage(req.Message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := ValidateSignature(req.Signature); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := ValidatePublicKey(req.PublicKey); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	block, _ := pem.Decode([]byte(req.PublicKey))
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse public key"})
		return
	}

	hash := sha512.Sum512([]byte(req.Message))
	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature format"})
		return
	}

	err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), 0, hash[:], signature)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"match": false})
	} else {
		c.JSON(http.StatusOK, gin.H{"match": true})
	}
}
