// internal/files/manager.go
package files

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unitpilot/internal/db"
)

type FileType string

const (
	TypeCron    FileType = "cron"
	TypeSystemd FileType = "systemd"
)

type FileManager struct {
	db      *db.DB
	baseDir string
}

func NewFileManager(database *db.DB, baseDir string) *FileManager {
	os.MkdirAll(filepath.Join(baseDir, "cron"), 0755)
	os.MkdirAll(filepath.Join(baseDir, "systemd"), 0755)
	return &FileManager{
		db:      database,
		baseDir: baseDir,
	}
}

func (fm *FileManager) GetFilePath(fileType FileType, filename string) string {
	return filepath.Join(fm.baseDir, string(fileType), filename)
}

func (fm *FileManager) ValidateFileName(filename string, fileType FileType) error {
	filename = filepath.Base(filename)

	if fileType == TypeCron && !strings.HasSuffix(filename, ".sh") {
		return fmt.Errorf("cron scripts must have .sh extension")
	}

	if fileType == TypeSystemd && !strings.HasSuffix(filename, ".service") {
		return fmt.Errorf("systemd files must have .service extension")
	}

	if strings.ContainsAny(filename, "/\\") {
		return fmt.Errorf("filename cannot contain path separators")
	}

	return nil
}

func (fm *FileManager) ValidateContent(content string, fileType FileType) error {
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("file content cannot be empty")
	}

	if fileType == TypeCron {
		if !strings.HasPrefix(strings.TrimSpace(content), "#!") {
			return fmt.Errorf("cron script should start with shebang (#!/bin/bash)")
		}
	}

	if fileType == TypeSystemd {
		if !strings.Contains(content, "[Unit]") && !strings.Contains(content, "[Service]") {
			return fmt.Errorf("systemd file should contain [Unit] or [Service] section")
		}
	}

	return nil
}

func (fm *FileManager) CreateFile(filename string, fileType FileType, content string) (*db.File, error) {
	if err := fm.ValidateFileName(filename, fileType); err != nil {
		return nil, err
	}

	if err := fm.ValidateContent(content, fileType); err != nil {
		return nil, err
	}

	file := &db.File{
		Filename: filepath.Base(filename),
		FileType: string(fileType),
		Content:  content,
		Size:     int64(len(content)),
	}

	if err := fm.db.CreateFile(file); err != nil {
		return nil, err
	}

	fullPath := fm.GetFilePath(fileType, file.Filename)
	permissions := os.FileMode(0644)
	if fileType == TypeCron {
		permissions = 0755
	}

	if err := os.WriteFile(fullPath, []byte(content), permissions); err != nil {
		fm.db.DeleteFile(file.ID)
		return nil, err
	}

	return file, nil
}

func (fm *FileManager) GetFile(id int) (*db.File, error) {
	file, err := fm.db.GetFile(id)
	if err != nil {
		return nil, err
	}

	fullPath := fm.GetFilePath(FileType(file.FileType), file.Filename)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	file.Content = string(content)
	return file, nil
}

func (fm *FileManager) GetFileByName(filename string, fileType FileType) (*db.File, error) {
	file, err := fm.db.GetFileByName(filename, string(fileType))
	if err != nil {
		return nil, err
	}

	fullPath := fm.GetFilePath(fileType, filename)
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	file.Content = string(content)
	return file, nil
}

func (fm *FileManager) UpdateFile(id int, content string) error {
	file, err := fm.db.GetFile(id)
	if err != nil {
		return err
	}

	if err := fm.ValidateContent(content, FileType(file.FileType)); err != nil {
		return err
	}

	file.Content = content
	file.Size = int64(len(content))
	file.UpdatedAt = time.Now()

	if err := fm.db.UpdateFile(file); err != nil {
		return err
	}

	fullPath := fm.GetFilePath(FileType(file.FileType), file.Filename)
	permissions := os.FileMode(0644)
	if file.FileType == string(TypeCron) {
		permissions = 0755
	}

	return os.WriteFile(fullPath, []byte(content), permissions)
}

func (fm *FileManager) DeleteFile(id int) error {
	file, err := fm.db.GetFile(id)
	if err != nil {
		return err
	}

	// Check if file is in use
	inUse, err := fm.db.IsFileInUse(id)
	if err != nil {
		return err
	}
	if inUse {
		return fmt.Errorf("file is in use by cron jobs or systemd services")
	}

	fullPath := fm.GetFilePath(FileType(file.FileType), file.Filename)
	if err := os.Remove(fullPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return fm.db.DeleteFile(id)
}

func (fm *FileManager) ListFiles(fileType string) ([]db.File, error) {
	return fm.db.ListFiles(fileType)
}
