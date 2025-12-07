package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"unitpilot/internal/files"
)

func (s *Server) handleFilesList(w http.ResponseWriter, r *http.Request) {
	fileList, err := s.Files.ListFiles("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cronCount := 0
	systemdCount := 0
	for _, f := range fileList {
		if f.FileType == "cron" {
			cronCount++
		} else if f.FileType == "systemd" {
			systemdCount++
		}
	}

	data := map[string]interface{}{
		"Title":        "File Management",
		"ActivePage":   "files",
		"Files":        fileList,
		"CronCount":    cronCount,
		"SystemdCount": systemdCount,
	}

	if err := s.Tmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	fileType := r.FormValue("file_type")
	if fileType != "cron" && fileType != "systemd" {
		http.Error(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
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

	_, err = s.Files.CreateFile(header.Filename, files.FileType(fileType), string(content))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("File uploaded successfully"))
}

func (s *Server) handleFileCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	filename := r.FormValue("filename")
	fileType := r.FormValue("file_type")
	content := r.FormValue("content")

	if fileType != "cron" && fileType != "systemd" {
		http.Error(w, "Invalid file type", http.StatusBadRequest)
		return
	}

	_, err := s.Files.CreateFile(filename, files.FileType(fileType), content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("File created successfully"))
}

func (s *Server) handleFileView(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	file, err := s.Files.GetFile(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         file.ID,
		"filename":   file.Filename,
		"file_type":  file.FileType,
		"content":    file.Content,
		"size":       file.Size,
		"created_at": file.CreatedAt,
		"updated_at": file.UpdatedAt,
	})
}

func (s *Server) handleFileEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.FormValue("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	content := r.FormValue("content")

	err = s.Files.UpdateFile(id, content)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("File updated successfully"))
}

func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	err = s.Files.DeleteFile(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("File deleted successfully"))
}
