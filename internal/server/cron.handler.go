package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"unitpilot/internal/db"
)

func (s *Server) handleCronList(w http.ResponseWriter, r *http.Request) {
	jobs, err := s.Db.ListCronJobs()
	if err != nil {
		http.Error(w, "Failed to load cron jobs", http.StatusInternalServerError)
		return
	}

	// Get all cron files for the dropdown in create modal
	cronFiles, err := s.Db.ListFiles("cron")
	if err != nil {
		log.Printf("Error loading cron files: %v", err)
		cronFiles = []db.File{}
	}

	data := map[string]interface{}{
		"Title":      "Cron Jobs",
		"ActivePage": "cron",
		"Jobs":       jobs,
		"CronFiles":  cronFiles,
	}

	if err := s.Tmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

func (s *Server) handleCronCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle file_id if provided
	fileIDStr := r.FormValue("file_id")
	var fileID *int
	if fileIDStr != "" {
		id, err := strconv.Atoi(fileIDStr)
		if err == nil && id > 0 {
			fileID = &id
			// Get file to construct command
			file, err := s.Db.GetFile(id)
			if err == nil {
				// Store the file info for later use
				r.Form.Set("command", filepath.Join(s.Config.ScriptsDir, "cron", file.Filename))
			}
		}
	}

	job := &db.CronJob{
		UserName:    r.FormValue("user_name"),
		Schedule:    r.FormValue("schedule"),
		Command:     r.FormValue("command"),
		Description: r.FormValue("description"),
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

	// Link file to job if file_id was provided
	if fileID != nil {
		s.Db.LinkFileToJob(job.ID, *fileID)
	}

	if err := s.Cron.SyncToSystem(job.UserName); err != nil {
		log.Printf("Failed to sync crontab: %v", err)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Cron job created successfully"))
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

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Job updated successfully"))
}
func (s *Server) handleCronToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Job toggled successfully"))
}

func (s *Server) handleCronGet(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid job ID", http.StatusBadRequest)
		return
	}

	job, err := s.Db.GetCronJob(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":          job.ID,
		"user_name":   job.UserName,
		"schedule":    job.Schedule,
		"command":     job.Command,
		"description": job.Description,
		"enabled":     job.Enabled,
	})
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
