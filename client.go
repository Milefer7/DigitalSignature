package DigitalSignature

func InitRouter(e *gin.Engine) {
	e.POST("/genSign", genSign)
	e.POST("/verify", Verify)
}
