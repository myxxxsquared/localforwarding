package localforwardingapp

type Config struct {
	Cidrs      []string `yaml:"cidr"`
	Main       bool     `yaml:"main"`
	Password   string   `yaml:"password"`
	Port       int      `yaml:"port"`
	LocalCidrs []string `yaml:"local_cidr"`

	DurationRenew     int `yaml:"duration_renew"`
	DurationKeepalive int `yaml:"duration_keepalive"`
	DurationRetry     int `yaml:"duration_retry"`
}
