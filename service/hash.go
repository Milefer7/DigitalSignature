package service

import (
	"crypto/sha512"
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GenerateHash(c *gin.Context) {
	var request struct {
		Message string `json:"message"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	hash := sha512.Sum512([]byte(request.Message))
	c.JSON(http.StatusOK, gin.H{"hash": hex.EncodeToString(hash[:])}) // 将字节流转为16进制字符串
}
