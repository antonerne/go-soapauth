package controller

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"go-soapauth/communications"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	models "github.com/antonerne/go-soap/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	gomail "gopkg.in/mail.v2"

	"gorm.io/gorm"
)

type UserController struct {
	DB        *gorm.DB
	ErrorLog  *models.LogFile
	AccessLog *models.LogFile
}

func (e *UserController) GetUser(c *gin.Context) {
	userid := c.Param("id")
	if userid != "" {
		var user models.User
		e.DB.Preload("Name").Preload("Creds").Where("id = ?", userid).
			Find(&user)
		var studies []models.UserBibleStudy
		e.DB.Preload("Periods.StudyDays.References").
			Where("userid = ?", userid).Where("startdate <= ?", time.Now()).
			Where("enddate >= ?", time.Now()).Find(&studies)
		user.Studies = append(user.Studies, studies...)
		c.JSON(http.StatusOK, gin.H{
			"user": user,
		})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"error": "No User ID provided",
	})
}

func (e *UserController) AddUser(c *gin.Context) {
	var newUser communications.NewUserRequest
	if err := c.BindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No Request Data - " + err.Error(),
		})
		return
	}

	var olduser models.User

	e.DB.Where("email = ?", newUser.Email).Find(&olduser)

	if olduser.ID != "" {
		c.JSON(http.StatusConflict, gin.H{
			"error": "Email Address already in use",
		})
		return
	}

	user := new(models.User)
	user.ID = uuid.NewString()
	user.Email = newUser.Email
	user.Name.First = newUser.FirstName
	user.Name.Middle = newUser.MiddleName
	user.Name.Last = newUser.LastName
	user.Name.Suffix = newUser.NameSuffix

	_, uerr := user.Creds.SetPassword(newUser.Password)
	if uerr != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Error Creating User - " + uerr.Message,
		})
		return
	}

	e.DB.Create(&user)

	token := user.Creds.StartVerification()

	err := e.SendVerificationEmail(user, token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Problem Sending Verification Message",
		})
	}
	c.JSON(http.StatusCreated, gin.H{
		"message": "Verification Email Sent",
	})
}

func (e *UserController) SendVerificationEmail(user *models.User,
	token string) error {

	t, err := template.ParseFiles("email.template.html")
	if err != nil {
		return err
	}

	data := struct {
		Subject string
		Message string
		Link    string
	}{
		Subject: "SOAP Bible Study Email Confirmation",
		Message: `You must verify your email address in the system before you
			are allowed to log into the system.  Use the following token string
			to verify your email address.  Type it in the space provided by the
			web site.`,
		Link: token,
	}

	fmt.Println(user.Email)

	buffer := new(bytes.Buffer)
	if err := t.Execute(buffer, data); err != nil {
		return err
	}
	body := buffer.String()

	mailer := gomail.NewMessage()

	mailer.SetHeader("From", os.Getenv("SMTP_FROM_EMAIL"))
	mailer.SetHeader("To", user.Email)
	mailer.SetHeader("Subject", data.Subject)
	mailer.SetBody("text/html", body)

	port, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	dialer := gomail.NewDialer(os.Getenv("SMTP_SERVER"), port,
		os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASSWORD"))
	dialer.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := dialer.DialAndSend(mailer); err != nil {
		return err
	}
	return nil
}

func (u *UserController) UpdateUser(c *gin.Context) {
	var req communications.UpdateUserRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No Request Data - " + err.Error(),
		})
		return
	}

	var user models.User
	u.DB.Preload("Name").Preload("Creds.Remotes").
		Where("id = ? OR email = ?", req.ID, req.Email).Find(&user)

	switch strings.ToLower(req.Field) {
	case "email":
		user.Email = req.Value
		token := user.Creds.StartVerification()
		u.DB.Save(&user)
		u.SendVerificationEmail(&user, token)
		c.JSON(http.StatusOK, gin.H{
			"message": "Verification sent",
		})
		return
	case "first":
		user.Name.First = req.Value
		u.DB.Save(&user.Name)
	case "middle":
		user.Name.Middle = req.Value
		u.DB.Save(&user.Name)
	case "last":
		user.Name.Last = req.Value
		u.DB.Save(&user.Name)
	case "suffix":
		user.Name.Suffix = req.Value
		u.DB.Save(&user.Name)
	case "password":
		user.Creds.SetPassword(req.Value)
		u.DB.Save(&user.Creds)
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Update Complete",
	})
}

func (u *UserController) DeleteUser(c *gin.Context) {
	id := c.Param("id")
	if id != "" {
		u.DB.Where("id = ?", id).Delete(models.User{})
		c.JSON(http.StatusOK, gin.H{
			"message": "User deleted",
		})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{
		"error": "No ID provided for deletion",
	})
}
