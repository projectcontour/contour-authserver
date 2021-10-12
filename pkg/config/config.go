package config

import (
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// OIDCConfig
type OIDCConfig struct {
	Address string `yaml:"address"`

	ClusterName            string   `yaml:"clusterName"`
	IssuerURL              string   `yaml:"issuerURL"`
	ClientID               string   `yaml:"clientID"`
	ClientSecret           string   `yaml:"clientSecret"`
	AllowEmptyClientSecret bool     `yaml:"allowEmptyClientSecret"`
	RedirectURL            string   `yaml:"redirectURL"`  // http://gangway.auth.app.local:9080
	RedirectPath           string   `yaml:"redirectPath"` // /callback
	Scopes                 []string `yaml:"scopes"`
	UsernameClaim          string   `yaml:"usernameClaim"`
	EmailClaim             string   `yaml:"emailClaim"`
	ServeTLS               bool     `yaml:"serveTLS"`
	Audience               string   `yaml:"audience"`
	CacheTimeout           int32    `yaml:"cacheTimeout"`
	SkipIssuerCheck        bool     `yaml:"skipIssuerCheck"`

	// T decide wether should this be use
	SessionSecurityKey string `yaml:"sessionSecurityKey" envconfig:"SESSION_SECURITY_KEY"`
}

// NewConfig returns a Config struct from serialized config file
func NewConfig(configFile string) (*OIDCConfig, error) {

	cfg := &OIDCConfig{
		CacheTimeout:    40,
		SkipIssuerCheck: false,
	}

	if configFile != "" {
		data, err := ioutil.ReadFile(configFile)
		if err != nil {
			return nil, err
		}
		err = yaml.Unmarshal([]byte(data), cfg)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("Config file path is required")
	}

	err := cfg.Validate()
	if err != nil {
		return nil, err
	}

	if cfg.Address == "" {
		cfg.Address = ":9080"
	}

	return cfg, nil
}

// Validate verifies all properties of config struct are intialized
func (cfg *OIDCConfig) Validate() error {
	checks := []struct {
		bad    bool
		errMsg string
	}{
		{cfg.IssuerURL == "", "no IssuerURL specified"},
		{cfg.ClientID == "", "no clientID specified"},
		{cfg.ClientSecret == "" && !cfg.AllowEmptyClientSecret, "no clientSecret specified"},
		{cfg.RedirectURL == "", "no redirectURL specified"},
		{cfg.RedirectPath == "", "no redirectURL specified"},
	}

	for _, check := range checks {
		if check.bad {
			return fmt.Errorf("invalid config: %s", check.errMsg)
		}
	}
	return nil
}
