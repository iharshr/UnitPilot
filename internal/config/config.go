package config

type Config struct {
	DBPath          string   `yaml:"db_path"`
	ListenAddr      string   `yaml:"listen_addr"`
	SessionSecret   string   `yaml:"session_secret"`
	SystemdPrefixes []string `yaml:"systemd_prefixes"`
	LogExportURL    string   `yaml:"log_export_url"`
	ScriptsDir      string   `yaml:"scripts_dir"`
	SystemdDir      string   `yaml:"systemd_dir"`
}
