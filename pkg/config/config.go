package config

import (
	"fmt"
	"io/ioutil"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

// OIDCConfig ...
type OIDCConfig struct {
	Address string `yaml:"address"`

	ClusterName            string   `yaml:"clusterName" envconfig:"cluster_name"`
	IssuerURL              string   `yaml:"issuerURL" envconfig:"issuer_url"`
	ClientID               string   `yaml:"clientID" envconfig:"client_id"`
	ClientSecret           string   `yaml:"clientSecret" envconfig:"client_secret"`
	AllowEmptyClientSecret bool     `yaml:"allowEmptyClientSecret" envconfig:"allow_empty_client_secret"`
	RedirectURL            string   `yaml:"redirectURL" envconfig:"redirect_url"`   // http://gangway.auth.app.local:9080
	RedirectPath           string   `yaml:"redirectPath" envconfig:"redirect_path"` // /callback
	Scopes                 []string `yaml:"scopes" envconfig:"scopes"`
	UsernameClaim          string   `yaml:"usernameClaim" envconfig:"username_claim"`
	EmailClaim             string   `yaml:"emailClaim" envconfig:"email_claim"`
	ServeTLS               bool     `yaml:"serveTLS" envconfig:"serve_tls"`
	Audience               string   `yaml:"audience" envconfig:"audience"`

	// TODO :: decide wether should this be use
	SessionSecurityKey string `yaml:"sessionSecurityKey" envconfig:"SESSION_SECURITY_KEY"`
}

// NewConfig returns a Config struct from serialized config file
func NewConfig(configFile string) (*OIDCConfig, error) {

	cfg := &OIDCConfig{
		Address:                ":9001",
		IssuerURL:              "http://dex.auth.app.local:9080",
		RedirectURL:            "http://192.168.1.134:9500",
		RedirectPath:           "/callback",
		AllowEmptyClientSecret: false,
		Scopes:                 []string{"openid", "profile", "email", "offline_access"},
		UsernameClaim:          "nickname",
		EmailClaim:             "",
		ServeTLS:               false,
		ClientID:               "bender",
		ClientSecret:           "googledocs",
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
	}

	err := envconfig.Process("contour-auth", cfg)
	if err != nil {
		return nil, err
	}

	err = cfg.Validate()
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
