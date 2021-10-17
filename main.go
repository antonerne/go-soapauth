package main

import (
	"context"
	"fmt"
	"go-soapauth/controller"
	"log"
	"os"
	"time"

	"github.com/Team-Scheduler/goteam/models/logs"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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
	dsn := os.Getenv("DBCONNECT")
	if dsn == "" {
		dsn = fmt.Sprintf("mongodb://%s:%s@%s:%s",
			os.Getenv("DBUSER"), os.Getenv("SBPASSWD"), os.Getenv("DBHOST"),
			os.Getenv("DBPORT"))
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(dsn))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	db := client.Database("soap")

	accessLog := logs.LogFile{Directory: os.Getenv("LOGLOCATION"), FileType: "Access"}
	errorLog := logs.LogFile{Directory: os.Getenv("LOGLOCATION"), FileType: "Error"}
	controller := controller.Controller{DB: db, AccessLog: &accessLog,
		ErrorLog: &errorLog}

	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("", controller.Login)
			auth.PUT("", controller.RefreshToken)
			auth.DELETE("", controller.Logout)
			auth.GET("verify/:token", controller.VerifyEmailAddress)
			auth.PUT("password", controller.ChangePassword)
			auth.GET("forgot/:token", controller.ForgotPasswordTwo)
			auth.POST("forgot", controller.ForgotPasswordThree)
			auth.PUT("forgot", controller.ForgotPasswordOne)
		}
	}
	r.GET("/alive", controller.AliveCheck)
	r.GET("/healthy", controller.HealthCheck)

	r.Run(":5001")
}
