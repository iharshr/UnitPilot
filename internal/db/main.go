package db

import (
	"database/sql"
	"time"

	"golang.org/x/crypto/bcrypt"
)

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

type ScriptFile struct {
	Name    string
	Path    string
	Size    int64
	ModTime time.Time
	Content string
}

type User struct {
	ID           int
	Username     string
	PasswordHash string
	IsAdmin      bool
	CreatedAt    time.Time
}

type File struct {
	ID        int
	Filename  string
	FileType  string
	Content   string
	Size      int64
	CreatedAt time.Time
	UpdatedAt time.Time
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
		file_id INTEGER,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (file_id) REFERENCES files(id)
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
	
	CREATE TABLE IF NOT EXISTS files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		filename TEXT NOT NULL,
		file_type TEXT NOT NULL,
		content TEXT NOT NULL,
		size INTEGER NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(filename, file_type)
	);

	CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON log_entries(timestamp);
	CREATE INDEX IF NOT EXISTS idx_logs_source ON log_entries(source);
	CREATE INDEX IF NOT EXISTS idx_files_type ON files(file_type);
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

func (db *DB) CreateFile(file *File) error {
	result, err := db.Exec(`
		INSERT INTO files (filename, file_type, content, size, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, file.Filename, file.FileType, file.Content, file.Size, time.Now(), time.Now())

	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	file.ID = int(id)
	file.CreatedAt = time.Now()
	file.UpdatedAt = time.Now()
	return nil
}

func (db *DB) GetFile(id int) (*File, error) {
	file := &File{}
	err := db.QueryRow(`
		SELECT id, filename, file_type, content, size, created_at, updated_at
		FROM files WHERE id = ?
	`, id).Scan(&file.ID, &file.Filename, &file.FileType, &file.Content,
		&file.Size, &file.CreatedAt, &file.UpdatedAt)

	return file, err
}

func (db *DB) GetFileByName(filename, fileType string) (*File, error) {
	file := &File{}
	err := db.QueryRow(`
		SELECT id, filename, file_type, content, size, created_at, updated_at
		FROM files WHERE filename = ? AND file_type = ?
	`, filename, fileType).Scan(&file.ID, &file.Filename, &file.FileType,
		&file.Content, &file.Size, &file.CreatedAt, &file.UpdatedAt)

	return file, err
}

func (db *DB) UpdateFile(file *File) error {
	_, err := db.Exec(`
		UPDATE files 
		SET content = ?, size = ?, updated_at = ?
		WHERE id = ?
	`, file.Content, file.Size, file.UpdatedAt, file.ID)

	return err
}

func (db *DB) DeleteFile(id int) error {
	_, err := db.Exec("DELETE FROM files WHERE id = ?", id)
	return err
}

func (db *DB) ListFiles(fileType string) ([]File, error) {
	query := `
		SELECT id, filename, file_type, size, created_at, updated_at
		FROM files
	`
	args := []interface{}{}

	if fileType != "" {
		query += " WHERE file_type = ?"
		args = append(args, fileType)
	}

	query += " ORDER BY updated_at DESC"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []File
	for rows.Next() {
		var f File
		err := rows.Scan(&f.ID, &f.Filename, &f.FileType, &f.Size,
			&f.CreatedAt, &f.UpdatedAt)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}

	return files, nil
}

func (db *DB) IsFileInUse(fileID int) (bool, error) {
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM cron_jobs WHERE file_id = ?
	`, fileID).Scan(&count)

	return count > 0, err
}

func (db *DB) LinkFileToJob(jobID, fileID int) error {
	_, err := db.Exec("UPDATE cron_jobs SET file_id = ? WHERE id = ?", fileID, jobID)
	return err
}

func (db *DB) GetAllCronJobs() ([]CronJob, error) {
	return db.ListCronJobs()
}

func (db *DB) GetRecentLogs(limit int) ([]LogEntry, error) {
	return db.GetLogs(limit, "", "")
}

func (db *DB) GetFilesByType(fileType string) ([]File, error) {
	return db.ListFiles(fileType)
}
