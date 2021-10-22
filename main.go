package main

import (
	"fmt"
	"go-soapauth/controller"
	"log"
	"os"

	"github.com/antonerne/go-soap/models"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// @title Team-Scheduler Authentication Microservice
// @version 1.0
// @description This microservice will handle all authentication actions
//
// @contact.name Team-Scheduler Support
// @contact.url https://team-scheduler.com/support
// @contact.email antonerne@team-scheduler.com
//
// @license.name Apache 2.0
// @License.url http://www.apache.org/licenses/LICENSE-2.0.html
//
// @host localhost:5001
// @BasePath /api/v1
// @query.collection.format multi
//
// @securityDefinitions.apiKey ApiKeyAuth
// @in header
// @name Authorization

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}
	r := gin.Default()

	// create database connection as a pool.
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s",
		os.Getenv("DBHOST"), os.Getenv("DBUSER"), os.Getenv("DBPASSWD"),
		os.Getenv("DATABASE"), os.Getenv("DBPORT"))
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	accessLog := models.LogFile{Directory: os.Getenv("LOGLOCATION"), FileType: "Access"}
	errorLog := models.LogFile{Directory: os.Getenv("LOGLOCATION"), FileType: "Error"}
	control := controller.Controller{DB: db, AccessLog: &accessLog,
		ErrorLog: &errorLog}
	userControl := controller.UserController{DB: db, AccessLog: &accessLog,
		ErrorLog: &errorLog}

	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("", control.Login)
			auth.PUT("", control.RefreshToken)
			auth.DELETE("", control.Logout)
			auth.GET("verify/:token", control.VerifyEmailAddress)
			auth.GET("remote/:token", control.ApproveRemote)
			auth.PUT("password", control.ChangePassword)
			auth.POST("forgot", control.ForgotPassword)
			auth.PUT("forgot", control.ForgotPasswordChange)
		}

		user := auth.Group("/users")
		{
			user.GET("/:id", models.AuthorizeJWT(db, &errorLog), userControl.GetUser)
			user.POST("/", userControl.AddUser)
			user.PUT("/", models.AuthorizeJWT(db, &errorLog), userControl.UpdateUser)
			user.DELETE("/:id", models.AuthorizeJWT(db, &errorLog),
				userControl.DeleteUser)
		}
	}

	r.Run(":6001")
}
