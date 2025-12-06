package cron

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unitpilot/internal/db"
)

type CronManager struct {
	db         *db.DB
	scriptsDir string
}

func NewCronManager(db *db.DB, scriptsDir string) *CronManager {
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

func (cm *CronManager) ListAllCrontabs() ([]db.CronJob, error) {
	var allJobs []db.CronJob

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

func (cm *CronManager) ReadFromSystem(userName string) ([]db.CronJob, error) {
	cmd := exec.Command("crontab", "-u", userName, "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "no crontab") {
			return nil, nil
		}
		return nil, nil
	}

	var jobs []db.CronJob
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
			job := db.CronJob{
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

	cm.db.LogEntry(&db.LogEntry{
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

func (cm *CronManager) ListScripts() ([]db.ScriptFile, error) {
	files, err := os.ReadDir(cm.scriptsDir)
	if err != nil {
		return nil, err
	}

	var scripts []db.ScriptFile
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		info, err := file.Info()
		if err != nil {
			continue
		}

		scripts = append(scripts, db.ScriptFile{
			Name:    file.Name(),
			Path:    filepath.Join(cm.scriptsDir, file.Name()),
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	return scripts, nil
}

func (cm *CronManager) GetScript(filename string) (*db.ScriptFile, error) {
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

	return &db.ScriptFile{
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
