package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

type ServerConfig struct {
	SocketTimeout struct {
		External time.Duration `yaml:"external"`
		Local    time.Duration `yaml:"local"`
	} `yaml:"socktimeout"`

	FilePaths struct {
		TokensDirPath string `yaml:"tokensdir"`
		AclFilePath   string `yaml:"aclfile"`
	} `yaml:"filepaths"`

	Ports struct {
		Issuer    int `yaml:"issuer"`
		Verifier  int `yaml:"verifier"`
		Dashboard int `yaml:"dashboard"`
	} `yaml:"ports"`

	Certs struct {
		CaCertFilePath     string `yaml:"cacert"`
		ServerCertFilePath string `yaml:"servercert"`
		ServerKeyFilePath  string `yaml:"serverkey"`
	} `yaml:"certs"`
}

type ClientConfig struct {
	SocketTimeout struct {
		External time.Duration `yaml:"external"`
		Local    time.Duration `yaml:"local"`
	} `yaml:"socktimeout"`

	FilePaths struct {
		TokensDirPath string `yaml:"tokensdir"`
	} `yaml:"filepaths"`

	IssuerAddr string `yaml:"issueraddr"`

	Certs struct {
		CaCertFilePath     string `yaml:"cacert"`
		ClientCertFilePath string `yaml:"clientcert"`
		ClientKeyFilePath  string `yaml:"clientkey"`
	} `yaml:"certs"`
}

var (
	Server ServerConfig
	Client ClientConfig
)

func LoadServerConfig(configFilePath string) (err error) {
	var f *os.File
	f, err = os.Open(configFilePath)
	if err != nil {
		return
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&Server)
	return
}

func LoadClientConfig(configFilePath string) (err error) {
	var f *os.File
	f, err = os.Open(configFilePath)
	if err != nil {
		return
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&Client)
	return
}
