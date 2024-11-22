package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/gin-gonic/gin"
)

type KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func GetKeys(c *gin.Context) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // rand.Reader是随机数生成器 生成的是一个符合 PKCS#1 格式的私钥。
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Key generation failed"})
		return
	}

	publicKey := &privateKey.PublicKey

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey) // 转为DER格式的字节流 MarshalPKCS1PrivateKey生成PKCS#1格式的私钥
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{            // 将DER格式的字节流转为PEM文本格式
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Public key encoding failed"})
		return
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Return keys as JSON
	c.JSON(http.StatusOK, KeyPair{
		PrivateKey: string(privateKeyPEM),
		PublicKey:  string(publicKeyPEM),
	})
}
