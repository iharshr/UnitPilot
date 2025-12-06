package systemd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unitpilot/internal/db"
)

type SystemdManager struct {
	db         *db.DB
	prefixes   []string
	systemdDir string
}

func NewSystemdManager(db *db.DB, prefixes []string, systemdDir string) *SystemdManager {
	os.MkdirAll(systemdDir, 0755)
	return &SystemdManager{db: db, prefixes: prefixes, systemdDir: systemdDir}
}

func (sm *SystemdManager) ListUnits() ([]db.SystemdUnit, error) {
	cmd := exec.Command("systemctl", "list-units", "--all", "--no-pager", "--plain", "--type=service")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var units []db.SystemdUnit
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

		unit := db.SystemdUnit{
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

	sm.db.LogEntry(&db.LogEntry{
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

	sm.db.LogEntry(&db.LogEntry{
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

	sm.db.LogEntry(&db.LogEntry{
		Timestamp: time.Now(),
		Source:    "systemd",
		UnitName:  name,
		Level:     "info",
		Message:   fmt.Sprintf("Restarted unit %s", name),
	})

	return err
}
