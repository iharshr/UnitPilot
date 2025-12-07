package server

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

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
