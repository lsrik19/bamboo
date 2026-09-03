package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds all the hyper-parameters and settings for Bamboo
type Config struct {
	// Capture Settings
	PcapPath  string `yaml:"pcap_path"`
	Interface string `yaml:"interface"`
	SnapLen   int32  `yaml:"snap_len"`
	CSVOutput string `yaml:"csv_output"`

	// Bamboo Model Settings
	NumFeatures   int     `yaml:"num_features"`
	MaxClusterM   int     `yaml:"max_cluster_m"`
	FMGracePeriod int     `yaml:"fm_grace_period"`
	ADGracePeriod int     `yaml:"ad_grace_period"`
	ThresholdBeta float64 `yaml:"threshold_beta"`

	// Observability Settings
	MetricsEnabled bool   `yaml:"metrics_enabled"`
	MetricsPort    int    `yaml:"metrics_port"`
	LogLevel       string `yaml:"log_level"`
	TestMode       bool   `yaml:"test_mode"`
}

// LoadConfig reads the YAML configuration file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml: %w", err)
	}

	return &cfg, nil
}
