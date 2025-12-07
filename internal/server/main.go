package server

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"reflect"
	"time"
	"unitpilot/internal/config"
	"unitpilot/internal/cron"
	"unitpilot/internal/db"
	"unitpilot/internal/files"
	"unitpilot/internal/systemd"

	"github.com/gorilla/sessions"
)

type Server struct {
	Db      *db.DB
	Config  *config.Config
	Store   *sessions.CookieStore
	Tmpl    *template.Template
	Cron    *cron.CronManager
	Systemd *systemd.SystemdManager
	Files   *files.FileManager
}

func NewServer(config *config.Config, templateFS embed.FS) (*Server, error) {
	db, err := db.NewDB(config.DBPath)
	if err != nil {
		return nil, err
	}

	if config.ScriptsDir == "" {
		config.ScriptsDir = "./files"
	}
	if config.SystemdDir == "" {
		config.SystemdDir = "./systemd-units"
	}

	// Template helper functions
	fm := template.FuncMap{
		// Format bytes to human readable
		"humanizeBytes": func(b int64) string {
			const unit = 1024
			if b < unit {
				return fmt.Sprintf("%d B", b)
			}
			div, exp := int64(unit), 0
			for n := b / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
		},

		// Create a dict/map for passing multiple parameters to templates
		"dict": func(values ...interface{}) (map[string]interface{}, error) {
			if len(values)%2 != 0 {
				return nil, fmt.Errorf("dict expects even number of arguments")
			}
			dict := make(map[string]interface{}, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, ok := values[i].(string)
				if !ok {
					return nil, fmt.Errorf("dict keys must be strings")
				}
				dict[key] = values[i+1]
			}
			return dict, nil
		},

		// String equality check
		"eq": func(a, b interface{}) bool {
			return a == b
		},

		// Negate boolean
		"not": func(b bool) bool {
			return !b
		},

		// Format time with Go layout
		"formatTime": func(t time.Time, layout string) string {
			return t.Format(layout)
		},

		// Check if value is nil
		"isNil": func(v interface{}) bool {
			return v == nil
		},

		// String concatenation
		"printf": fmt.Sprintf,

		// Add numbers
		"add": func(a, b int) int {
			return a + b
		},

		// Subtract numbers
		"sub": func(a, b int) int {
			return a - b
		},

		// Get length of slice/array/map
		"len": func(v interface{}) int {
			val := reflect.ValueOf(v)
			switch val.Kind() {
			case reflect.Array, reflect.Slice, reflect.Map, reflect.String:
				return val.Len()
			default:
				return 0
			}
		},
	}

	// Create template with FuncMap BEFORE parsing
	tmpl := template.New("").Funcs(fm)

	// Parse all templates including components and pages
	tmpl, err = tmpl.ParseFS(templateFS,
		"templates/components/*.html",
		"templates/pages/*.html")
	if err != nil {
		return nil, err
	}

	store := sessions.NewCookieStore([]byte(config.SessionSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	return &Server{
		Db:      db,
		Config:  config,
		Store:   store,
		Tmpl:    tmpl,
		Cron:    cron.NewCronManager(db, config.ScriptsDir),
		Systemd: systemd.NewSystemdManager(db, config.SystemdPrefixes, config.SystemdDir),
		Files:   files.NewFileManager(db, config.ScriptsDir),
	}, nil
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	jobs, _ := s.Db.ListCronJobs()
	units, _ := s.Systemd.ListUnits()
	logs, _ := s.Db.GetLogs(10, "", "")

	data := map[string]interface{}{
		"Title":      "Dashboard",
		"ActivePage": "dashboard",
		"CronJobs":   jobs,
		"Units":      units,
		"Logs":       logs,
	}

	if err := s.Tmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Auth routes
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	// Dashboard
	mux.HandleFunc("/", s.requireAuth(s.handleDashboard))

	// Cron routes
	mux.HandleFunc("/cron", s.requireAuth(s.handleCronList))
	mux.HandleFunc("/cron/get", s.requireAuth(s.handleCronGet))
	mux.HandleFunc("/cron/create", s.requireAdmin(s.handleCronCreate))
	mux.HandleFunc("/cron/edit", s.requireAdmin(s.handleCronEdit))
	mux.HandleFunc("/cron/toggle", s.requireAdmin(s.handleCronToggle))
	mux.HandleFunc("/cron/run", s.requireAdmin(s.handleCronRunNow))
	mux.HandleFunc("/cron/delete", s.requireAdmin(s.handleCronDelete))

	// Script management routes (kept for backward compatibility)
	mux.HandleFunc("/scripts/upload", s.requireAdmin(s.handleScriptUpload))
	mux.HandleFunc("/scripts/view", s.requireAuth(s.handleScriptView))
	mux.HandleFunc("/scripts/edit", s.requireAdmin(s.handleScriptEdit))
	mux.HandleFunc("/scripts/delete", s.requireAdmin(s.handleScriptDelete))

	// Systemd routes
	mux.HandleFunc("/systemd", s.requireAuth(s.handleSystemdList))
	mux.HandleFunc("/systemd/action", s.requireAdmin(s.handleSystemdAction))
	mux.HandleFunc("/systemd/view", s.requireAuth(s.handleSystemdViewFile))
	mux.HandleFunc("/systemd/edit", s.requireAdmin(s.handleSystemdEditFile))

	// Logs routes
	mux.HandleFunc("/logs", s.requireAuth(s.handleLogs))
	mux.HandleFunc("/api/logs/export", s.requireAuth(s.handleLogsExport))

	// File management routes
	mux.HandleFunc("/files", s.requireAuth(s.handleFilesList))
	mux.HandleFunc("/files/upload", s.requireAdmin(s.handleFileUpload))
	mux.HandleFunc("/files/create", s.requireAdmin(s.handleFileCreate))
	mux.HandleFunc("/files/view", s.requireAuth(s.handleFileView))
	mux.HandleFunc("/files/edit", s.requireAdmin(s.handleFileEdit))
	mux.HandleFunc("/files/delete", s.requireAdmin(s.handleFileDelete))

	log.Printf("Starting server on %s", s.Config.ListenAddr)
	return http.ListenAndServe(s.Config.ListenAddr, mux)
}
