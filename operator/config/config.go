package config

import (
	"github.com/microsoft/retina/pkg/config"
	"github.com/spf13/viper"
)

type OperatorConfig struct {
	config.CaptureConfig `mapstructure:",squash"`

	InstallCRDs     bool   `yaml:"installCRDs"`
	EnableTelemetry bool   `yaml:"enableTelemetry"`
	LogLevel        string `yaml:"logLevel"`
	// EnableRetinaEndpoint indicates whether to enable RetinaEndpoint
	EnableRetinaEndpoint bool `yaml:"enableRetinaEndpoint"`
	RemoteContext        bool `yaml:"remoteContext"`
}

func GetConfig(cfgFileName string) (*OperatorConfig, error) {
	viper.SetConfigType("yaml")
	viper.SetConfigFile(cfgFileName)
	err := viper.ReadInConfig()
	if err != nil {
		return nil, err
	}

	viper.AutomaticEnv()

	var cfg OperatorConfig

	// Check pkg/config/config.go for the explanation of setting EnableRetinaEndpoint defaults to true.
	viper.SetDefault("EnableRetinaEndpoint", true)
	err = viper.Unmarshal(&cfg)

	return &cfg, err
}
