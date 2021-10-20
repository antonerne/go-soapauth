package controller

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"go-soapauth/communications"
	"net/http"
	"os"
	"strconv"
	"text/template"
	"time"

	models "github.com/antonerne/go-soap/models"
	"gorm.io/gorm"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"

	gomail "gopkg.in/mail.v2"
)

type Controller struct {
	DB        *gorm.DB
	ErrorLog  *models.LogFile
	AccessLog *models.LogFile
}

// Login godoc
// @Summary Authenticate user
// @Description Authenticate user with string email address and password
// @ID authenticate-user
// @Accept json
// @Produce json
// @Param request body communications.AuthenticationRequest true "request"
// @Success 200 {object} communications.LoginResponse
// @Failure 400,401,404 {object} communications.ErrorMessage
// @Router /auth [post]
func (con *Controller) Login(c *gin.Context) {
	// get request from the context
	var request communications.AuthenticationRequest
	if err := c.BindJSON(&request); err == nil {
		// get requested user
		var user models.User

		con.DB.Preload("Name").Preload("Creds.Remotes").
			Preload("Studies.Periods.StudyDays.References").
			Where("email = ?", request.Email).Find(&user)

		if user.ID != "" {
			// user found, so now compare the password authentication
			_, err := user.Creds.LogIn(request.Password, c.ClientIP())
			if err != nil {
				if err.Message == "Account Not Verified" {
					verifyToken := user.Creds.StartVerification()
					uerr := con.DB.Save(&user.Creds).Error
					if uerr != nil {
						c.JSON(http.StatusNotFound, gin.H{
							"error": "Update Error: " + uerr.Error(),
						})
						return
					}
					serr := con.SendVerificationEmail(&user, verifyToken)
					if serr != nil {
						con.ErrorLog.WriteToLog(serr.Error())
					}
				}
				if err.Message == "New Remote" {
					status := err.StatusCode
					// send new client ip message.
					remoteToken := user.Creds.StartRemoteToken()
					c.JSON(int(status), gin.H{
						"error": "New Remote",
					})
					user.Creds.BadAttempts = 0
					user.Creds.Locked = false
					con.DB.Save(&user.Creds)
					con.SendNewComputerEmail(&user, remoteToken)
					return
				}
				con.DB.Save(&user)
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": err.Message,
				})
				return
			}

			tokenString, token, terr := user.Creds.CreateJWTToken(
				user.ID, user.Email, user.Editor, "")
			con.DB.Create(&token)
			if terr != nil {
				aerr := &communications.ErrorMessage{
					ErrorType:  "credentials",
					StatusCode: http.StatusBadRequest,
					Message:    "Unable to Create JWT Token: " + terr.Error(),
				}
				con.ErrorLog.WriteToLog(aerr.String())
				c.JSON(http.StatusBadRequest, gin.H{
					"error": aerr.Message,
				})
				return
			}
			accessMsg := fmt.Sprintf("%s - Logged In", user.Name.FullName())
			con.AccessLog.WriteToLog(accessMsg)
			c.JSON(http.StatusOK, gin.H{
				"token": tokenString,
			})
			return
		}
		err := communications.ErrorMessage{
			ErrorType:  "user",
			StatusCode: http.StatusNotFound,
			Message:    "No User for Email Address",
		}
		con.ErrorLog.WriteToLog(err.String())
		c.JSON(int(err.StatusCode), gin.H{
			"error": err.Message,
		})
	}
}

func (con *Controller) SendVerificationEmail(user *models.User,
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

func (con *Controller) SendNewComputerEmail(user *models.User,
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
		Subject: "SOAP Bible Study Remote Verification",
		Message: `It appears you are trying to access the site from a new 
			computer/device.  Please use the code provided to verify the new
			computer access.`,
		Link: token,
	}

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

// Logout godoc
// @Summary Remove Token and Note Logout
// @Description Actions to remove token reference from database and annotate the user's logout
// @ID logout-user
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {string} string
// @Failure 400,401,404 {string} string
// @Router /auth [delete]
func (con *Controller) Logout(c *gin.Context) {
	// get the current JWT token UUID and delete it from the database
	// add log entry for the log out.
	creds := new(models.Credentials)
	authHeader := c.GetHeader("Authorization")
	tokenString := authHeader[len("Bearer")+1:]
	token, err := creds.ValidateToken(tokenString)
	if token.Valid {
		claims := creds.GetClaims(token.Claims.(jwt.MapClaims))
		var user models.User

		uerr := con.DB.Preload("Name").Where("id = ?", claims.Id).Find(&user).Error
		if uerr != nil {
			con.ErrorLog.WriteToLog(uerr.Error())
		}

		uerr = con.DB.Where("id = ?", claims.Uuid).Delete(models.Token{}).Error
		if uerr != nil {
			con.ErrorLog.WriteToLog(uerr.Error())
			return
		}

		con.AccessLog.WriteToLog(fmt.Sprintf("%s Logged Out", user.Name.FullName()))
	} else {
		cErr := &communications.ErrorMessage{
			ErrorType:  "unknown",
			StatusCode: http.StatusBadRequest,
			Message:    fmt.Sprintf("%s: %s", "Verification Failed", err.Error()),
		}
		con.ErrorLog.WriteToLog(cErr.String())
		t, _ := template.ParseFiles("error.template.html")
		buffer := new(bytes.Buffer)
		if err := t.Execute(buffer, cErr); err != nil {
			fmt.Println(err)
			con.ErrorLog.WriteToLog(err.Error())
		}
		body := buffer.String()

		c.Data(int(cErr.StatusCode), "text/html; charset=utf-8", []byte(body))
	}
}

// EmailVerification godoc
// @Summary Email Verification
// @Description Complete Email Verification process and return HTML
// @ID verify-email
// @Accept json
// @Produce html
// @Param token path string true "verification token"
// @Success 200 {string} string
// @Failure 400,401,404 {string} string
// @Router /auth/verify/{token} [get]
func (con *Controller) VerifyEmailAddress(c *gin.Context) {
	// get the verification code in the parameters
	verifyToken := c.Param("token")
	var cred models.Credentials

	con.DB.Where("verificationtoken = ?", verifyToken).Find(&cred)

	if cred.UserID != "" {
		verified, cErr := cred.Verify(verifyToken)
		if cErr != nil || !verified {
			if !verified && cErr == nil {
				cErr = &models.ErrorMessage{
					ErrorType:  "unknown",
					StatusCode: http.StatusBadRequest,
					Message:    "Verification Failed",
				}
				con.ErrorLog.WriteToLog(cErr.String())
			}
			c.JSON(int(cErr.StatusCode), gin.H{
				"error": cErr.Message,
			})
			return
		}
		con.DB.Save(&cred)

		c.JSON(http.StatusOK, gin.H{
			"message": "Account Verified",
		})
	} else {
		cErr := &communications.ErrorMessage{
			ErrorType:  "unknown",
			StatusCode: http.StatusBadRequest,
			Message:    "Verification Failed",
		}
		c.JSON(int(cErr.StatusCode), gin.H{
			"error": cErr.Message,
		})
	}
}

// RefreshToken godoc
// @Summary Obtain new JWT Token
// @Description Actions for swapping a new authorized token for an old one
// @ID renew-jwt
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} communications.LoginResponse
// @Failure 400,401,404 {object} communications.ErrorMessage
// @Router /auth [put]
func (con *Controller) RefreshToken(c *gin.Context) {
	// first get the current token from the header.  If valid, create a new
	// token from the data in the current token and return it.
	creds := new(models.Credentials)
	authHeader := c.GetHeader("Authorization")
	tokenString := authHeader[len("Bearer")+1:]
	token, err := creds.ValidateToken(tokenString)
	if token.Valid {
		claims := creds.GetClaims(token.Claims.(jwt.MapClaims))

		con.DB.Where("id = ?", claims.Uuid).Delete(models.Token{})

		tokenString, tk, err := creds.CreateJWTToken(claims.Id, claims.Email,
			claims.Editor, "")
		if err != nil {
			con.ErrorLog.WriteToLog(err.Error())
			cErr := communications.ErrorMessage{
				ErrorType:  "credentials",
				StatusCode: http.StatusNotAcceptable,
				Message:    err.Error(),
			}
			c.JSON(http.StatusNotAcceptable, gin.H{
				"error": cErr.Message,
			})
			return
		}
		con.DB.Create(&tk)
		accessMsg := fmt.Sprintf("%s - Token Refreshed", claims.Id)
		con.AccessLog.WriteToLog(accessMsg)
		c.JSON(http.StatusOK, gin.H{
			"token": tokenString,
		})
	} else {
		con.ErrorLog.WriteToLog(err.Error())
		fmt.Println(err)
		cErr := communications.ErrorMessage{
			ErrorType:  "credentials",
			StatusCode: http.StatusNotAcceptable,
			Message:    err.Error(),
		}
		c.JSON(http.StatusNotAcceptable, gin.H{
			"error": cErr.Message,
		})
	}
}

// ApproveRemote godoc
// @Summary Approve new computer or device for use
// @Description This routine will add the current client IP Address to the user's
// list of approved computers and devices.
func (con *Controller) ApproveRemote(c *gin.Context) {
	verifyToken := c.Param("token")
	var user models.User
	var cred models.Credentials
	con.DB.Where("newremotetoken = ?", verifyToken).Find(&cred)

	if cred.UserID != "" {
		cred.NewRemoteToken = ""
		con.DB.Save(&cred)

		con.DB.Preload("Name").Preload("Creds.Remotes").
			Where("id = ?", cred.UserID).Find(&user)

		if !user.Creds.HasRemote(c.ClientIP()) {
			remote := models.UserRemote{
				CredentialsUserID: user.ID,
				RemoteIP:          c.ClientIP(),
			}
			con.DB.Create(&remote)
			user.Creds.Remotes = append(user.Creds.Remotes, remote)
		}

		accessMsg := fmt.Sprintf("%s - Logged In", user.Name.FullName())
		con.AccessLog.WriteToLog(accessMsg)
		c.JSON(http.StatusOK, gin.H{
			"message": "Remote Added",
		})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{
		"error": "Remote Token not found",
	})
}

// ChangePassword godoc
// @Summary Obtain new JWT Token
// @Description Actions for swapping a new authorized token for an old one
// @ID change-password
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body communications.NewPasswordRequest true "New Password Information"
// @Success 200 {object} communications.LoginResponse
// @Failure 400,401,404 {object} communications.ErrorMessage
// @Router /auth/password [put]
func (con *Controller) ChangePassword(c *gin.Context) {
	creds := new(models.Credentials)
	authHeader := c.GetHeader("Authorization")
	tokenString := authHeader[len("Bearer")+1:]
	token, err := creds.ValidateToken(tokenString)

	if token.Valid {
		var request communications.NewPasswordRequest
		if err = c.BindJSON(&request); err == nil {
			var user models.User

			con.DB.Preload("Name").Preload("Creds").Preload("Remotes").
				Preload("Studies.Periods.StudyDays.References").
				Where("id = ?", request.UserID).Find(&user)

			login, cErr := user.Creds.LogIn(request.OldPassword, c.ClientIP())
			if !login || cErr != nil {
				if cErr != nil {
					con.ErrorLog.WriteToLog(cErr.String())
					c.JSON(http.StatusNotAcceptable, gin.H{
						"error": cErr.Message,
					})
				} else {
					cErr = &models.ErrorMessage{
						ErrorType:  "credentials",
						StatusCode: http.StatusNonAuthoritativeInfo,
						Message:    "Bad Password",
					}
					c.JSON(int(cErr.StatusCode), gin.H{
						"error": cErr.Message,
					})
				}
				return
			}

			user.Creds.SetPassword(request.NewPassword)

			con.DB.Save(&user.Creds)

			claims := user.Creds.GetClaims(token.Claims.(jwt.MapClaims))
			tokenString, tk, err := user.Creds.CreateJWTToken(user.ID,
				user.Email, user.Editor, "")
			if err != nil {
				con.ErrorLog.WriteToLog(err.Error())
				cErr := communications.ErrorMessage{
					ErrorType:  "credentials",
					StatusCode: http.StatusNotAcceptable,
					Message:    err.Error(),
				}
				c.JSON(http.StatusNotAcceptable, gin.H{
					"error": cErr.Message,
				})
				return
			}

			con.DB.Where("id = ?", claims.Uuid).Delete(models.Token{})
			con.DB.Create(&tk)

			accessMsg := fmt.Sprintf("%s - Logged In", user.Name.FullName())
			con.AccessLog.WriteToLog(accessMsg)
			c.JSON(http.StatusOK, gin.H{
				"token": tokenString,
			})
		}
	} else {
		con.ErrorLog.WriteToLog(err.Error())
		fmt.Println(err)
		cErr := communications.ErrorMessage{
			ErrorType:  "credentials",
			StatusCode: http.StatusNotAcceptable,
			Message:    err.Error(),
		}
		c.JSON(http.StatusNotAcceptable, gin.H{
			"error": cErr.Message,
		})
	}
}

// Start Forgot Password (godoc)
// @Summary Start Forgot Password Process
// @Description Process email address in the forgot password process
// @ID forgot-password-put
// @Accept json
// @Produce json
// @Param request body communications.ForgotPasswordStartRequest true "User's Email Address"
// @Success 200 {string} message
// @Failure 400,401,404 {object} communications.ErrorMessage
// @Router /auth/forgot [put]
func (con *Controller) ForgotPassword(c *gin.Context) {
	// step one is the default step of sending the user an email with the
	// forgot password (reset) token.  This is based on the user's email
	// address.
	var forgotStart communications.ForgotPasswordStartRequest
	if err := c.BindJSON(&forgotStart); err == nil {
		var user models.User

		con.DB.Preload("Name").Preload("Creds").Preload("Remotes").
			Preload("Studies.Periods.StudyDays.References").
			Where("email = ?", forgotStart.Email).Find(&user)

		token := user.Creds.StartForgot()

		con.DB.Save(&user.Creds)

		if user.ID != "" {
			t, err := template.ParseFiles("email.template.html")
			if err != nil {
				c.JSON(http.StatusNotAcceptable, gin.H{
					"error": err.Error(),
				})
			}

			data := struct {
				Subject string
				Message string
				Link    string
			}{
				Subject: "Soap Bible Study Forgot Password",
				Message: `Since you forgot your password, this message is to 
					provide a piece of the puzzle.  The code provided will be 
					included in your request.  Type in the code below into the 
					forgot password page, along with a new password (twice).`,
				Link: token,
			}

			buffer := new(bytes.Buffer)
			if err := t.Execute(buffer, data); err != nil {
				c.JSON(http.StatusNotAcceptable, gin.H{
					"error": err.Error(),
				})
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
				c.JSON(http.StatusNotAcceptable, gin.H{
					"error": err,
				})
			}
			c.JSON(http.StatusOK, gin.H{
				"message": "Email Sent",
			})
		} else {
			cErr := communications.ErrorMessage{
				ErrorType:  "user",
				StatusCode: http.StatusNotFound,
				Message:    "No user for Email Address Given",
			}
			c.JSON(int(cErr.StatusCode), gin.H{
				"error": cErr.Message,
			})
		}
	} else {
		cErr := communications.ErrorMessage{
			ErrorType:  "request",
			StatusCode: http.StatusBadRequest,
			Message:    err.Error(),
		}
		c.JSON(int(cErr.StatusCode), gin.H{
			"error": cErr.Message,
		})
	}
}

// Step 2 Forgot Password (godoc)
// @Summary Receive Reset Token to provide forgot password web page.
// @Description Process reset token to create a web page for changing the user password.
// @ID forgot-password-get
// @Accept plain
// @Produce html
// @Param token path string true "Reset Token"
// @Success 200 {html} resetpassword
// @Failure 400,401,404 {object} communications.ErrorMessage
// @Router /auth/forgot/{token} [get]
func (con *Controller) ForgotPasswordChange(c *gin.Context) {
	var request communications.ForgotPasswordChangeRequest
	if err := c.BindJSON(&request); err == nil {
		var user models.User

		con.DB.Preload("Name").Preload("Creds").Preload("Remotes").
			Preload("Studies.Periods.StudyDays.References").
			Where("id = ?", request.UserID).Find(&user)

		if user.ID != "" {

			if user.Creds.ResetToken == request.ResetToken {
				user.Creds.SetPassword(request.NewPassword)
				user.Creds.ResetToken = ""
				user.Creds.ResetExpires = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
				con.DB.Save(&user.Creds)
				c.JSON(http.StatusOK, gin.H{
					"message": "Password Changed",
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Reset Token doesn't match",
			})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User Not Found",
		})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"error": "Request Data Malformed",
	})
}
