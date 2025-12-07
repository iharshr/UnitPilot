package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	level := r.URL.Query().Get("level")
	limit := 100

	logs, err := s.Db.GetLogs(limit, source, level)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title":      "Activity Logs",
		"ActivePage": "logs",
		"Logs":       logs,
	}

	if err := s.Tmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
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
