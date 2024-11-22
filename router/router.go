package router

import (
	"DigitalSignature/middleware"
	"DigitalSignature/service"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine) {
	r.Use(middleware.CORSMiddleware())
	r.GET("/api/keys", service.GetKeys)
	r.POST("/api/hash", service.GenerateHash)
	r.POST("/api/sign", service.GenerateSignature)
	r.POST("/api/send", service.SendMessage)
	r.POST("/api/receive", service.ReceiveMessage)
	r.GET("/api/sse", service.SSE)
	r.POST("/api/compare", service.CompareHash)
}
