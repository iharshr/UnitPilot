// UniPilot Admin - Enhanced Version with File Management
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*
var templateFS embed.FS

type Config struct {
	DBPath          string   `yaml:"db_path"`
	ListenAddr      string   `yaml:"listen_addr"`
	SessionSecret   string   `yaml:"session_secret"`
	SystemdPrefixes []string `yaml:"systemd_prefixes"`
	LogExportURL    string   `yaml:"log_export_url"`
	ScriptsDir      string   `yaml:"scripts_dir"`
	SystemdDir      string   `yaml:"systemd_dir"`
}

type User struct {
	ID           int
	Username     string
	PasswordHash string
	IsAdmin      bool
	CreatedAt    time.Time
}

type CronJob struct {
	ID          int
	UserName    string
	Schedule    string
	Command     string
	Enabled     bool
	LastRun     *time.Time
	LastExit    *int
	Description string
	ScriptPath  string
	CreatedAt   time.Time
}

type SystemdUnit struct {
	Name        string
	Description string
	LoadState   string
	ActiveState string
	SubState    string
	LastExit    int
	FilePath    string
}

type LogEntry struct {
	ID        int
	Timestamp time.Time
	Source    string
	JobID     string
	UnitName  string
	Level     string
	Message   string
	ExitCode  *int
}

type ScriptFile struct {
	Name    string
	Path    string
	Size    int64
	ModTime time.Time
	Content string
}

type DB struct {
	*sql.DB
}

func NewDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		is_admin BOOLEAN DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS cron_jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_name TEXT NOT NULL,
		schedule TEXT NOT NULL,
		command TEXT NOT NULL,
		enabled BOOLEAN DEFAULT 1,
		last_run TIMESTAMP,
		last_exit INTEGER,
		description TEXT,
		script_path TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS log_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		source TEXT NOT NULL,
		job_id TEXT,
		unit_name TEXT,
		level TEXT NOT NULL,
		message TEXT NOT NULL,
		exit_code INTEGER
	);
	
	CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON log_entries(timestamp);
	CREATE INDEX IF NOT EXISTS idx_logs_source ON log_entries(source);
	`

	_, err = db.Exec(schema)
	if err != nil {
		return nil, err
	}

	return &DB{db}, nil
}

func (db *DB) CreateUser(username, password string, isAdmin bool) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
		username, string(hash), isAdmin)
	return err
}

func (db *DB) GetUser(username string) (*User, error) {
	u := &User{}
	err := db.QueryRow("SELECT id, username, password_hash, is_admin, created_at FROM users WHERE username = ?",
		username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsAdmin, &u.CreatedAt)
	return u, err
}

func (db *DB) ListCronJobs() ([]CronJob, error) {
	rows, err := db.Query(`
		SELECT id, user_name, schedule, command, enabled, last_run, last_exit, description, script_path, created_at 
		FROM cron_jobs ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []CronJob
	for rows.Next() {
		var j CronJob
		var scriptPath sql.NullString
		err := rows.Scan(&j.ID, &j.UserName, &j.Schedule, &j.Command, &j.Enabled,
			&j.LastRun, &j.LastExit, &j.Description, &scriptPath, &j.CreatedAt)
		if err != nil {
			return nil, err
		}
		if scriptPath.Valid {
			j.ScriptPath = scriptPath.String
		}
		jobs = append(jobs, j)
	}
	return jobs, nil
}

func (db *DB) GetCronJob(id int) (*CronJob, error) {
	var j CronJob
	var scriptPath sql.NullString
	err := db.QueryRow(`
		SELECT id, user_name, schedule, command, enabled, last_run, last_exit, description, script_path, created_at 
		FROM cron_jobs WHERE id = ?
	`, id).Scan(&j.ID, &j.UserName, &j.Schedule, &j.Command, &j.Enabled,
		&j.LastRun, &j.LastExit, &j.Description, &scriptPath, &j.CreatedAt)
	if err != nil {
		return nil, err
	}
	if scriptPath.Valid {
		j.ScriptPath = scriptPath.String
	}
	return &j, nil
}

func (db *DB) CreateCronJob(job *CronJob) error {
	var scriptPath interface{}
	if job.ScriptPath != "" {
		scriptPath = job.ScriptPath
	}

	result, err := db.Exec(`
		INSERT INTO cron_jobs (user_name, schedule, command, enabled, description, script_path)
		VALUES (?, ?, ?, ?, ?, ?)
	`, job.UserName, job.Schedule, job.Command, job.Enabled, job.Description, scriptPath)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	job.ID = int(id)
	return nil
}

func (db *DB) UpdateCronJob(id int, enabled bool) error {
	_, err := db.Exec("UPDATE cron_jobs SET enabled = ? WHERE id = ?", enabled, id)
	return err
}

func (db *DB) UpdateCronJobFull(id int, schedule, command, description string) error {
	_, err := db.Exec("UPDATE cron_jobs SET schedule = ?, command = ?, description = ? WHERE id = ?",
		schedule, command, description, id)
	return err
}

func (db *DB) DeleteCronJob(id int) error {
	_, err := db.Exec("DELETE FROM cron_jobs WHERE id = ?", id)
	return err
}

func (db *DB) LogEntry(entry *LogEntry) error {
	_, err := db.Exec(`
		INSERT INTO log_entries (timestamp, source, job_id, unit_name, level, message, exit_code)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, entry.Timestamp, entry.Source, entry.JobID, entry.UnitName, entry.Level, entry.Message, entry.ExitCode)
	return err
}

func (db *DB) GetLogs(limit int, source, level string) ([]LogEntry, error) {
	query := "SELECT id, timestamp, source, job_id, unit_name, level, message, exit_code FROM log_entries WHERE 1=1"
	args := []interface{}{}

	if source != "" {
		query += " AND source = ?"
		args = append(args, source)
	}
	if level != "" {
		query += " AND level = ?"
		args = append(args, level)
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []LogEntry
	for rows.Next() {
		var l LogEntry
		err := rows.Scan(&l.ID, &l.Timestamp, &l.Source, &l.JobID, &l.UnitName, &l.Level, &l.Message, &l.ExitCode)
		if err != nil {
			return nil, err
		}
		logs = append(logs, l)
	}
	return logs, nil
}

type CronManager struct {
	db         *DB
	scriptsDir string
}

func NewCronManager(db *DB, scriptsDir string) *CronManager {
	os.MkdirAll(scriptsDir, 0755)
	return &CronManager{db: db, scriptsDir: scriptsDir}
}

func (cm *CronManager) ValidateSchedule(schedule string) error {
	parts := strings.Fields(schedule)
	if len(parts) != 5 {
		return fmt.Errorf("cron schedule must have 5 fields")
	}
	return nil
}

func (cm *CronManager) ListAllCrontabs() ([]CronJob, error) {
	var allJobs []CronJob

	cmd := exec.Command("sh", "-c", "cut -d: -f1 /etc/passwd")
	output, err := cmd.Output()
	if err != nil {
		return allJobs, nil
	}

	users := strings.Split(string(output), "\n")
	for _, user := range users {
		if user == "" || user == "nobody" {
			continue
		}

		jobs, _ := cm.ReadFromSystem(user)
		allJobs = append(allJobs, jobs...)
	}

	return allJobs, nil
}

func (cm *CronManager) ReadFromSystem(userName string) ([]CronJob, error) {
	cmd := exec.Command("crontab", "-u", userName, "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "no crontab") {
			return nil, nil
		}
		return nil, nil
	}

	var jobs []CronJob
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "# unipilot-id:") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 6 {
			continue
		}

		schedule := strings.Join(parts[0:5], " ")
		command := strings.Join(parts[5:], " ")

		dbJobs, _ := cm.db.ListCronJobs()
		exists := false
		for _, job := range dbJobs {
			if job.Schedule == schedule && job.Command == command && job.UserName == userName {
				exists = true
				jobs = append(jobs, job)
				break
			}
		}

		if !exists {
			job := CronJob{
				UserName:    userName,
				Schedule:    schedule,
				Command:     command,
				Enabled:     true,
				Description: "Imported from system crontab",
			}
			jobs = append(jobs, job)
		}
	}

	return jobs, nil
}

func (cm *CronManager) SyncToSystem(userName string) error {
	jobs, err := cm.db.ListCronJobs()
	if err != nil {
		return err
	}

	var lines []string
	lines = append(lines, "# UniPilot Admin Managed Crontab")
	lines = append(lines, "# Do not edit manually - changes will be overwritten")
	lines = append(lines, "")

	for _, job := range jobs {
		if job.UserName == userName && job.Enabled {
			if job.Description != "" {
				lines = append(lines, fmt.Sprintf("# %s (ID: %d)", job.Description, job.ID))
			}
			cronLine := fmt.Sprintf("%s %s # unipilot-id:%d", job.Schedule, job.Command, job.ID)
			lines = append(lines, cronLine)
			lines = append(lines, "")
		}
	}

	content := strings.Join(lines, "\n")

	cmd := exec.Command("crontab", "-u", userName, "-")
	cmd.Stdin = strings.NewReader(content)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to write crontab: %v - %s", err, string(output))
	}

	return nil
}

func (cm *CronManager) RunNow(jobID int) error {
	job, err := cm.db.GetCronJob(jobID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	execCmd := exec.CommandContext(ctx, "sh", "-c", job.Command)
	output, err := execCmd.CombinedOutput()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	cm.db.LogEntry(&LogEntry{
		Timestamp: time.Now(),
		Source:    "cron",
		JobID:     strconv.Itoa(jobID),
		Level:     "info",
		Message:   string(output),
		ExitCode:  &exitCode,
	})

	now := time.Now()
	cm.db.Exec("UPDATE cron_jobs SET last_run = ?, last_exit = ? WHERE id = ?", now, exitCode, jobID)

	return nil
}

func (cm *CronManager) SaveScript(filename string, content []byte) (string, error) {
	filename = filepath.Base(filename)
	if !strings.HasSuffix(filename, ".sh") {
		filename = filename + ".sh"
	}

	fullPath := filepath.Join(cm.scriptsDir, filename)
	err := os.WriteFile(fullPath, content, 0755)
	return fullPath, err
}

func (cm *CronManager) ListScripts() ([]ScriptFile, error) {
	files, err := os.ReadDir(cm.scriptsDir)
	if err != nil {
		return nil, err
	}

	var scripts []ScriptFile
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		scripts = append(scripts, ScriptFile{
			Name:    file.Name(),
			Path:    filepath.Join(cm.scriptsDir, file.Name()),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	return scripts, nil
}

func (cm *CronManager) GetScript(filename string) (*ScriptFile, error) {
	filename = filepath.Base(filename)
	fullPath := filepath.Join(cm.scriptsDir, filename)

	info, err := os.Stat(fullPath)
	if err != nil {
		return nil, err
	}

	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	return &ScriptFile{
		Name:    filename,
		Path:    fullPath,
		Size:    info.Size(),
		ModTime: info.ModTime(),
		Content: string(content),
	}, nil
}

func (cm *CronManager) DeleteScript(filename string) error {
	filename = filepath.Base(filename)
	fullPath := filepath.Join(cm.scriptsDir, filename)
	return os.Remove(fullPath)
}

type SystemdManager struct {
	db         *DB
	prefixes   []string
	systemdDir string
}

func NewSystemdManager(db *DB, prefixes []string, systemdDir string) *SystemdManager {
	os.MkdirAll(systemdDir, 0755)
	return &SystemdManager{db: db, prefixes: prefixes, systemdDir: systemdDir}
}

func (sm *SystemdManager) ListUnits() ([]SystemdUnit, error) {
	cmd := exec.Command("systemctl", "list-units", "--all", "--no-pager", "--plain", "--type=service")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var units []SystemdUnit
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := fields[0]

		if len(sm.prefixes) > 0 {
			matched := false
			for _, prefix := range sm.prefixes {
				if strings.HasPrefix(name, prefix) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		unit := SystemdUnit{
			Name:        name,
			LoadState:   fields[1],
			ActiveState: fields[2],
			SubState:    fields[3],
		}

		if len(fields) > 4 {
			unit.Description = strings.Join(fields[4:], " ")
		}

		unit.FilePath = sm.GetUnitFilePath(name)
		units = append(units, unit)
	}

	return units, nil
}

func (sm *SystemdManager) GetUnitFilePath(unitName string) string {
	cmd := exec.Command("systemctl", "show", unitName, "-p", "FragmentPath", "--value")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func (sm *SystemdManager) GetUnitFileContent(unitName string) (string, error) {
	filePath := sm.GetUnitFilePath(unitName)
	if filePath == "" {
		return "", fmt.Errorf("unit file not found")
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

func (sm *SystemdManager) SaveUnitFile(unitName, content string) error {
	filename := filepath.Base(unitName)
	if !strings.HasSuffix(filename, ".service") {
		filename = filename + ".service"
	}

	fullPath := filepath.Join(sm.systemdDir, filename)
	err := os.WriteFile(fullPath, []byte(content), 0644)
	if err != nil {
		return err
	}

	systemPath := "/etc/systemd/system/" + filename
	copyCmd := exec.Command("cp", fullPath, systemPath)
	if err := copyCmd.Run(); err != nil {
		log.Printf("Warning: Could not copy to system directory: %v", err)
	}

	reloadCmd := exec.Command("systemctl", "daemon-reload")
	reloadCmd.Run()

	return nil
}

func (sm *SystemdManager) StartUnit(name string) error {
	cmd := exec.Command("systemctl", "start", name)
	err := cmd.Run()

	sm.db.LogEntry(&LogEntry{
		Timestamp: time.Now(),
		Source:    "systemd",
		UnitName:  name,
		Level:     "info",
		Message:   fmt.Sprintf("Started unit %s", name),
	})

	return err
}

func (sm *SystemdManager) StopUnit(name string) error {
	cmd := exec.Command("systemctl", "stop", name)
	err := cmd.Run()

	sm.db.LogEntry(&LogEntry{
		Timestamp: time.Now(),
		Source:    "systemd",
		UnitName:  name,
		Level:     "info",
		Message:   fmt.Sprintf("Stopped unit %s", name),
	})

	return err
}

func (sm *SystemdManager) RestartUnit(name string) error {
	cmd := exec.Command("systemctl", "restart", name)
	err := cmd.Run()

	sm.db.LogEntry(&LogEntry{
		Timestamp: time.Now(),
		Source:    "systemd",
		UnitName:  name,
		Level:     "info",
		Message:   fmt.Sprintf("Restarted unit %s", name),
	})

	return err
}

type Server struct {
	db      *DB
	config  *Config
	store   *sessions.CookieStore
	tmpl    *template.Template
	cron    *CronManager
	systemd *SystemdManager
}

func NewServer(config *Config) (*Server, error) {
	db, err := NewDB(config.DBPath)
	if err != nil {
		return nil, err
	}

	if config.ScriptsDir == "" {
		config.ScriptsDir = "./scripts"
	}
	if config.SystemdDir == "" {
		config.SystemdDir = "./systemd-units"
	}

	// --- ADD YOUR FUNC HERE ---
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
		db:      db,
		config:  config,
		store:   store,
		tmpl:    tmpl,
		cron:    NewCronManager(db, config.ScriptsDir),
		systemd: NewSystemdManager(db, config.SystemdPrefixes, config.SystemdDir),
	}, nil
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := s.store.Get(r, "session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		session, _ := s.store.Get(r, "session")
		if admin, ok := session.Values["is_admin"].(bool); !ok || !admin {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.tmpl.ExecuteTemplate(w, "login.html", nil)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := s.db.GetUser(username)
	if err != nil {
		s.tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		s.tmpl.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
		return
	}

	session, _ := s.store.Get(r, "session")
	session.Values["authenticated"] = true
	session.Values["username"] = user.Username
	session.Values["is_admin"] = user.IsAdmin
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := s.store.Get(r, "session")
	session.Values["authenticated"] = false
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	allCrons, _ := s.cron.ListAllCrontabs()
	jobs, _ := s.db.ListCronJobs()
	units, _ := s.systemd.ListUnits()
	logs, _ := s.db.GetLogs(10, "", "")

	data := map[string]interface{}{
		"CronJobs": jobs,
		"AllCrons": allCrons,
		"Units":    units,
		"Logs":     logs,
	}

	s.tmpl.ExecuteTemplate(w, "dashboard.html", data)
}

func (s *Server) handleCronList(w http.ResponseWriter, r *http.Request) {
	allCrons, _ := s.cron.ListAllCrontabs()
	jobs, _ := s.db.ListCronJobs()
	scripts, _ := s.cron.ListScripts()

	data := map[string]interface{}{
		"Jobs":     jobs,
		"AllCrons": allCrons,
		"Scripts":  scripts,
	}
	s.tmpl.ExecuteTemplate(w, "cron.html", data)
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

	path, err := s.cron.SaveScript(header.Filename, content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte(path))
}

func (s *Server) handleScriptView(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	script, err := s.cron.GetScript(filename)
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

	_, err := s.cron.SaveScript(filename, []byte(content))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Script saved successfully"))
}

func (s *Server) handleScriptDelete(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	err := s.cron.DeleteScript(filename)
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

	job := &CronJob{
		UserName:    r.FormValue("user_name"),
		Schedule:    r.FormValue("schedule"),
		Command:     r.FormValue("command"),
		Description: r.FormValue("description"),
		ScriptPath:  r.FormValue("script_path"),
		Enabled:     r.FormValue("enabled") == "on",
	}

	if err := s.cron.ValidateSchedule(job.Schedule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.db.CreateCronJob(job); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.cron.SyncToSystem(job.UserName); err != nil {
		log.Printf("Failed to sync crontab: %v", err)
	}

	jobs, _ := s.db.ListCronJobs()
	s.tmpl.ExecuteTemplate(w, "cron.html", map[string]interface{}{"Jobs": jobs})
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

	job, err := s.db.GetCronJob(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if err := s.db.UpdateCronJobFull(id, schedule, command, description); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.cron.SyncToSystem(job.UserName)

	w.Write([]byte("Job updated successfully"))
}

func (s *Server) handleCronToggle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	enabled := r.URL.Query().Get("enabled") == "true"

	job, err := s.db.GetCronJob(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.db.UpdateCronJob(id, enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.cron.SyncToSystem(job.UserName)

	jobs, _ := s.db.ListCronJobs()
	s.tmpl.ExecuteTemplate(w, "cron.html", map[string]interface{}{"Jobs": jobs})
}

func (s *Server) handleCronRunNow(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	go s.cron.RunNow(id)
	w.Write([]byte("Job started"))
}

func (s *Server) handleCronDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))

	job, err := s.db.GetCronJob(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	if err := s.db.DeleteCronJob(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.cron.SyncToSystem(job.UserName)

	w.Write([]byte("Job deleted"))
}

func (s *Server) handleSystemdList(w http.ResponseWriter, r *http.Request) {
	units, err := s.systemd.ListUnits()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{"Units": units}
	s.tmpl.ExecuteTemplate(w, "systemd.html", data)
}

func (s *Server) handleSystemdAction(w http.ResponseWriter, r *http.Request) {
	unit := r.URL.Query().Get("unit")
	action := r.URL.Query().Get("action")

	var err error
	switch action {
	case "start":
		err = s.systemd.StartUnit(unit)
	case "stop":
		err = s.systemd.StopUnit(unit)
	case "restart":
		err = s.systemd.RestartUnit(unit)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	time.Sleep(500 * time.Millisecond)
	units, _ := s.systemd.ListUnits()
	s.tmpl.ExecuteTemplate(w, "systemd.html", map[string]interface{}{"Units": units})
}

func (s *Server) handleSystemdViewFile(w http.ResponseWriter, r *http.Request) {
	unitName := r.URL.Query().Get("unit")

	content, err := s.systemd.GetUnitFileContent(unitName)
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

	err := s.systemd.SaveUnitFile(unitName, content)
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

	logs, err := s.db.GetLogs(limit, source, level)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{"Logs": logs}
	s.tmpl.ExecuteTemplate(w, "logs.html", data)
}

func (s *Server) handleLogsExport(w http.ResponseWriter, r *http.Request) {
	logs, err := s.db.GetLogs(1000, "", "")
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

	log.Printf("Starting server on %s", s.config.ListenAddr)
	return http.ListenAndServe(s.config.ListenAddr, mux)
}

func main() {
	configData, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal("Error reading config:", err)
	}

	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		log.Fatal("Error parsing config:", err)
	}

	if config.SessionSecret == "" {
		b := make([]byte, 32)
		rand.Read(b)
		config.SessionSecret = base64.StdEncoding.EncodeToString(b)
	}

	server, err := NewServer(&config)
	if err != nil {
		log.Fatal("Error creating server:", err)
	}

	_, err = server.db.GetUser("admin")
	if err == sql.ErrNoRows {
		log.Println("Creating default admin user (username: admin, password: admin)")
		server.db.CreateUser("admin", "admin", true)
	}

	log.Println("Importing existing crontab entries...")
	server.cron.ListAllCrontabs()

	if err := server.Start(); err != nil {
		log.Fatal("Error starting server:", err)
	}
}
