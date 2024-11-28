package main

import (
	"DigitalSignature/router"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	router.RegisterRoutes(r)
	//r.Run(":8081")
	r.Run(":8080")
}
