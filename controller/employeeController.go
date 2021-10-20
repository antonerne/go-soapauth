package controller

import (
	"net/http"

	models "github.com/antonerne/go-soap/models"
	"github.com/gin-gonic/gin"

	"gorm.io/gorm"
)

type EmployeeController struct {
	DB        *gorm.DB
	ErrorLog  *models.LogFile
	AccessLog *models.LogFile
}

func (e *EmployeeController) GetEmployee(c *gin.Context) {
	userid := c.Param("id")
	if userid != "" {
		var user models.User
		e.DB.Preload("Name").Preload("Creds").Where("id = ?", userid).
			Find(&user)
		var studies []models.BibleStudy
		e.DB.Preload("Periods.StudyDays.References").Where("userid = ?", userid).Where()
		c.JSON(http.StatusOK, gin.H{
			"user": user,
		})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{
		"error": "No User ID provided",
	})
}
