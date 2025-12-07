package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

func (s *Server) handleSystemdList(w http.ResponseWriter, r *http.Request) {
	units, err := s.Systemd.ListUnits()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title":      "Systemd Services",
		"ActivePage": "systemd",
		"Units":      units,
	}

	if err := s.Tmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
}

// systemd.handler.go - handleSystemdAction (updated to return full page)
func (s *Server) handleSystemdAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	// Wait a moment for state to update
	time.Sleep(500 * time.Millisecond)

	// Return the full page
	units, _ := s.Systemd.ListUnits()
	data := map[string]interface{}{
		"Title":      "Systemd Services",
		"ActivePage": "systemd",
		"Units":      units,
	}

	if err := s.Tmpl.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
	}
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
