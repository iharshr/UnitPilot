package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
	"unitpilot/internal/config"
	"unitpilot/internal/cron"
	"unitpilot/internal/db"
	"unitpilot/internal/systemd"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

type Server struct {
	Db      *db.DB
	Config  *config.Config
	Store   *sessions.CookieStore
	Tmpl    *template.Template
	Cron    *cron.CronManager
	Systemd *systemd.SystemdManager
}

func NewServer(config *config.Config, templateFS embed.FS) (*Server, error) {
	db, err := db.NewDB(config.DBPath)
	if err != nil {
		return nil, err
	}

	if config.ScriptsDir == "" {
		config.ScriptsDir = "./scripts"
	}
	if config.SystemdDir == "" {
		config.SystemdDir = "./systemd-units"
	}

	fm := template.FuncMap{
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
	}

	// Apply FuncMap BEFORE parsing templates
	tmpl := template.New("").Funcs(fm)

	// Parse from embed FS
	tmpl, err = tmpl.ParseFS(templateFS, "templates/*.html")
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
	}, nil
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := s.Store.Get(r, "session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		session, _ := s.Store.Get(r, "session")
		if admin, ok := session.Values["is_admin"].(bool); !ok || !admin {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.Tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := s.Db.GetUser(username)
	if err != nil {
		s.Tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		s.Tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
		return
	}

	session, _ := s.Store.Get(r, "session")
	session.Values["authenticated"] = true
	session.Values["username"] = user.Username
	session.Values["is_admin"] = user.IsAdmin
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := s.Store.Get(r, "session")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	allCrons, _ := s.Cron.ListAllCrontabs()
	jobs, _ := s.Db.ListCronJobs()
	units, _ := s.Systemd.ListUnits()
	logs, _ := s.Db.GetLogs(10, "", "")

	data := map[string]interface{}{
		"CronJobs": jobs,
		"AllCrons": allCrons,
		"Units":    units,
		"Logs":     logs,
	}

	s.Tmpl.ExecuteTemplate(w, "dashboard.html", data)
}

func (s *Server) handleCronList(w http.ResponseWriter, r *http.Request) {
	allCrons, _ := s.Cron.ListAllCrontabs()
	jobs, _ := s.Db.ListCronJobs()
	scripts, _ := s.Cron.ListScripts()

	data := map[string]interface{}{
		"Jobs":     jobs,
		"AllCrons": allCrons,
		"Scripts":  scripts,
	}
	s.Tmpl.ExecuteTemplate(w, "cron.html", data)
}

func (s *Server) handleScriptUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("script")
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file content", http.StatusInternalServerError)
		return
	}

	path, err := s.Cron.SaveScript(header.Filename, content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte(path))
}

func (s *Server) handleScriptView(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	script, err := s.Cron.GetScript(filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(script)
}

func (s *Server) handleScriptEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.FormValue("filename")
	content := r.FormValue("content")

	_, err := s.Cron.SaveScript(filename, []byte(content))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Script saved successfully"))
}

func (s *Server) handleScriptDelete(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	err := s.Cron.DeleteScript(filename)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Script deleted"))
}

func (s *Server) handleCronCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	job := &db.CronJob{
		UserName:    r.FormValue("user_name"),
		Schedule:    r.FormValue("schedule"),
		Command:     r.FormValue("command"),
		Description: r.FormValue("description"),
		ScriptPath:  r.FormValue("script_path"),
		Enabled:     r.FormValue("enabled") == "on",
	}

	if err := s.Cron.ValidateSchedule(job.Schedule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.Db.CreateCronJob(job); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.Cron.SyncToSystem(job.UserName); err != nil {
		log.Printf("Failed to sync crontab: %v", err)
	}

	jobs, _ := s.Db.ListCronJobs()
	s.Tmpl.ExecuteTemplate(w, "cron.html", map[string]interface{}{"Jobs": jobs})
}

func (s *Server) handleCronEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id, _ := strconv.Atoi(r.FormValue("id"))
	schedule := r.FormValue("schedule")
	command := r.FormValue("command")
	description := r.FormValue("description")

	job, err := s.Db.GetCronJob(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if err := s.Db.UpdateCronJobFull(id, schedule, command, description); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.Cron.SyncToSystem(job.UserName)

	w.Write([]byte("Job updated successfully"))
}

func (s *Server) handleCronToggle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	enabled := r.URL.Query().Get("enabled") == "true"

	job, err := s.Db.GetCronJob(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.Db.UpdateCronJob(id, enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.Cron.SyncToSystem(job.UserName)

	jobs, _ := s.Db.ListCronJobs()
	s.Tmpl.ExecuteTemplate(w, "cron.html", map[string]interface{}{"Jobs": jobs})
}

func (s *Server) handleCronRunNow(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	go s.Cron.RunNow(id)
	w.Write([]byte("Job started"))
}

func (s *Server) handleCronDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))

	job, err := s.Db.GetCronJob(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if err := s.Db.DeleteCronJob(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.Cron.SyncToSystem(job.UserName)

	w.Write([]byte("Job deleted"))
}

func (s *Server) handleSystemdList(w http.ResponseWriter, r *http.Request) {
	units, err := s.Systemd.ListUnits()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{"Units": units}
	s.Tmpl.ExecuteTemplate(w, "systemd.html", data)
}

func (s *Server) handleSystemdAction(w http.ResponseWriter, r *http.Request) {
	unit := r.URL.Query().Get("unit")
	action := r.URL.Query().Get("action")

	var err error
	switch action {
	case "start":
		err = s.Systemd.StartUnit(unit)
	case "stop":
		err = s.Systemd.StopUnit(unit)
	case "restart":
		err = s.Systemd.RestartUnit(unit)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	time.Sleep(500 * time.Millisecond)
	units, _ := s.Systemd.ListUnits()
	s.Tmpl.ExecuteTemplate(w, "systemd.html", map[string]interface{}{"Units": units})
}

func (s *Server) handleSystemdViewFile(w http.ResponseWriter, r *http.Request) {
	unitName := r.URL.Query().Get("unit")

	content, err := s.Systemd.GetUnitFileContent(unitName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"unit":    unitName,
		"content": content,
	})
}

func (s *Server) handleSystemdEditFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	unitName := r.FormValue("unit")
	content := r.FormValue("content")

	err := s.Systemd.SaveUnitFile(unitName, content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Unit file saved successfully"))
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	level := r.URL.Query().Get("level")
	limit := 100

	logs, err := s.Db.GetLogs(limit, source, level)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{"Logs": logs}
	s.Tmpl.ExecuteTemplate(w, "logs.html", data)
}

func (s *Server) handleLogsExport(w http.ResponseWriter, r *http.Request) {
	logs, err := s.Db.GetLogs(1000, "", "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	encoder := json.NewEncoder(w)

	for _, log := range logs {
		encoder.Encode(map[string]interface{}{
			"timestamp": log.Timestamp.Format(time.RFC3339),
			"source":    log.Source,
			"job_id":    log.JobID,
			"unit_name": log.UnitName,
			"level":     log.Level,
			"message":   log.Message,
			"exit_code": log.ExitCode,
		})
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/", s.requireAuth(s.handleDashboard))

	// Cron routes
	mux.HandleFunc("/cron", s.requireAuth(s.handleCronList))
	mux.HandleFunc("/cron/create", s.requireAdmin(s.handleCronCreate))
	mux.HandleFunc("/cron/edit", s.requireAdmin(s.handleCronEdit))
	mux.HandleFunc("/cron/toggle", s.requireAdmin(s.handleCronToggle))
	mux.HandleFunc("/cron/run", s.requireAdmin(s.handleCronRunNow))
	mux.HandleFunc("/cron/delete", s.requireAdmin(s.handleCronDelete))

	// Script management routes
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

	log.Printf("Starting server on %s", s.Config.ListenAddr)
	return http.ListenAndServe(s.Config.ListenAddr, mux)
}
