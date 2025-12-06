// UniPilot Admin - Enhanced Version with File Management
package main

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"log"
	"os"
	"unitpilot/internal/config"
	"unitpilot/internal/server"

	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*
var templateFS embed.FS

func main() {
	configData, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal("Error reading config:", err)
	}

	var config config.Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		log.Fatal("Error parsing config:", err)
	}

	if config.SessionSecret == "" {
		b := make([]byte, 32)
		rand.Read(b)
		config.SessionSecret = base64.StdEncoding.EncodeToString(b)
	}

	server, err := server.NewServer(&config, templateFS)
	if err != nil {
		log.Fatal("Error creating server:", err)
	}

	_, err = server.Db.GetUser("admin")
	if err == sql.ErrNoRows {
		log.Println("Creating default admin user (username: admin, password: admin)")
		server.Db.CreateUser("admin", "admin", true)
	}

	log.Println("Importing existing crontab entries...")
	server.Cron.ListAllCrontabs()

	if err := server.Start(); err != nil {
		log.Fatal("Error starting server:", err)
	}
}
