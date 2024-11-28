package service

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

type MessageRequest struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
	IP        string `json:"ip"`
}

type NewMessageRequest struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PublicKey string `json:"public_key"`
}

var messageChannel = make(chan []byte, 100) // 用于保存消息的通道

func SendMessage(c *gin.Context) {
	var req MessageRequest
	//println("SendMessage")
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	//println("SendMessage2")

	newReq := NewMessageRequest{
		Message:   req.Message,
		Signature: req.Signature,
		PublicKey: req.PublicKey,
	}

	data, err := json.Marshal(newReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal request"})
		return
	}

	url := "http://" + req.IP + "/api/receive"
	//println("url: ", url)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(data))
	if err != nil || resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send message"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "success"})
}

func ReceiveMessage(c *gin.Context) {
	var req NewMessageRequest
	c.ShouldBindJSON(&req)

	message := gin.H{
		"message":    req.Message,
		"signature":  req.Signature,
		"public_key": req.PublicKey,
	}
	jsonData, _ := json.Marshal(message)

	// 测试是否接收到
	//formattedJSON, err := json.MarshalIndent(message, "", "  ")
	//if err != nil {
	//	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to format JSON"})
	//	return
	//}
	//println("jsonData: ", string(formattedJSON))

	// 将消息发送到消息通道
	select {
	case messageChannel <- jsonData:
		// 成功写入通道
		c.JSON(http.StatusOK, gin.H{"status": "success"})
		//fmt.Printf("Received message: %s\n", jsonData)
	default:
		// 通道已满，返回错误
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Message channel is full"})
	}

}

// SSE SSE-based ReceiveMessage
func SSE(c *gin.Context) {
	// Set headers for SSE
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")

	// Flusher is needed to push data immediately
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Streaming unsupported"})
		return
	}

	for {
		select {
		case jsonData := <-messageChannel:
			fmt.Fprintf(c.Writer, "data: %s\n\n", jsonData)
			flusher.Flush() // Push data to client immediately
		case <-time.After(2 * time.Second):
			// No new message, send a heartbeat to keep the connection alive
			fmt.Fprintf(c.Writer, "data: {}\n\n")
			flusher.Flush()
		}
	}
}

func CompareHash(c *gin.Context) {
	var req NewMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	//fmt.Printf("req: %+v\n", req)

	// 使用 SHA-512 对消息进行哈希
	hash := sha512.New()
	hash.Write([]byte(req.Message)) // 写入消息
	hashedMessage := hash.Sum(nil)  // 生成哈希值
	//fmt.Printf("hashedMessage: %x/n/n/n", hashedMessage)
	//hashedMessageHex := hex.EncodeToString(hashedMessage)

	// 解密签名，得到消息摘要
	decryptedHash, err, match := decryptWithPublicKey(req.Signature, req.PublicKey, hashedMessage)
	if err != nil {
		//如果错误是签名无效类型，则返回签名无效
		if err.Error() == "signature invalid" {
			c.JSON(http.StatusOK, gin.H{"error": "Signature invalid"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt signature"})
		return
	}

	// 返回结果
	c.JSON(http.StatusOK, gin.H{
		"decrypted_hash": decryptedHash,
		"hashed_message": hashedMessage,
		"match":          match,
	})
}

// decryptWithPublicKey 用于使用公钥解密签名
// 从 PEM 格式解码公钥。
// 解析公钥。
// 从 base64 解码签名。
// 使用 RSA 公钥解密签名。
// 验证签名的函数
func decryptWithPublicKey(signature, publicKey string, hashedMessage []byte) (string, error, bool) {
	println("signature: ", signature)
	println("")
	println("hashedMessage: ", hex.EncodeToString(hashedMessage))
	println("")
	println("publicKey: ", publicKey)

	// 1. 解析 PEM 格式的公钥
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		println("err1: failed to decode PEM block containing RSA public key")
		return "", fmt.Errorf("failed to decode PEM block containing RSA public key"), false
	}

	// 2. 判断公钥类型并解析
	var rsaPub *rsa.PublicKey
	var err error

	// 尝试 PKCS#1 格式
	rsaPub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		// 如果不是 PKCS#1 格式，尝试解析 PKCS#8 格式
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			println("err2: failed to parse public key (both PKCS#1 and PKCS#8 failed)")
			return "", fmt.Errorf("failed to parse public key: %v", err), false
		}

		// 确保解析结果是 RSA 公钥
		var ok bool
		rsaPub, ok = pubKey.(*rsa.PublicKey)
		if !ok {
			println("err3: parsed public key is not RSA")
			return "", fmt.Errorf("parsed public key is not RSA"), false
		}
	}

	// 3. Base64 解码签名
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		println("err4: failed to decode signature")
		return "", fmt.Errorf("failed to decode signature: %v", err), false
	}

	//fmt.Printf("rsaPub: %v\n", rsaPub)
	//fmt.Printf("signature: %x\n", signature)
	//fmt.Printf("hashedMessage: %x\n", hashedMessage)
	//fmt.Printf("sigBytes: %x\n", sigBytes)

	//4. 使用 RSA 公钥验证签名 传入参数为公钥、哈希算法、消息摘要、签名
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA512, hashedMessage[:], sigBytes)
	if err != nil {
		fmt.Printf("err5: signature verification failed: %v\n", err)
		return "", fmt.Errorf("signature invalid"), false
	}

	// 对比解密后的签名和消息摘要
	//fmt.Println("公钥加密encryptedSignature: " + string(encryptedSignatureStr))
	//fmt.Println("")
	//fmt.Println("原签名signature: " + signature)

	// 5. 返回成功消息
	return hex.EncodeToString(hashedMessage), nil, true
}
