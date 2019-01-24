package main

import (
	"fmt"
	"net/http"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// User db struct
// type User struct {
// 	ID    int    `db:"id"`
// 	Email string `db:"email"`
// 	Password  string `db:"name"`
// }

type LoginRequest struct {
	ID       int    `db:"id"`
	Email    string `db:"email" json:"email" binding:"required"`
	Password string `db:"password" json:"password" binding:"required"`
}

func setupRouter(conn *sqlx.DB) *gin.Engine {
	r := gin.Default()

	// Ping test
	r.POST("/login", func(c *gin.Context) {
		var request LoginRequest
		var user LoginRequest

		c.BindJSON(&request)

		err := conn.Get(&user, "select id, email, password from users where email=?", request.Email)
		if err != nil {
			c.JSON(http.StatusOK, map[string]string{
				"status":  "error",
				"message": "Email not find!",
			})
			return
		}

		if CheckPasswordHash(request.Password, user.Password) {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"user_id": user.ID})
			tokenString, err := token.SignedString([]byte("signing_key"))
			if err == nil {
				c.JSON(http.StatusOK, map[string]string{"jwt": tokenString})
				return
			}
		}

		c.JSON(http.StatusOK, map[string]string{
			"status":  "error",
			"message": "Password not match!",
		})
	})

	return r
}

func setupConnection() *sqlx.DB {
	// Setup connection
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	db := os.Getenv("DB_DATABASE")
	username := os.Getenv("DB_USERNAME")
	password := os.Getenv("DB_PASSWORD")

	conn, err := sqlx.Connect("mysql", fmt.Sprintf("%s:%s@(%s:%s)/%s", username, password, host, port, db))
	if err != nil {
		panic(err)
	}

	return conn
}

func main() {
	connection := setupConnection()
	r := setupRouter(connection)
	// Listen and Server in 0.0.0.0:8080
	r.Run(":8080")
}
