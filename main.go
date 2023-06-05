package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/myxxxsquared/localforwarding/localforwardingapp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	configFile := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	yamlFile, err := os.ReadFile(*configFile)
	if err != nil {
		log.WithField("config", *configFile).WithError(err).Fatal("Error reading config file")
	}
	config := localforwardingapp.Config{}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.WithError(err).Fatal("Error parsing config file")
	}

	daemon, err := localforwardingapp.NewDaemon(&config)
	if err != nil {
		log.WithError(err).Fatal("Error creating daemon")
	}

	err = daemon.Start()
	if err != nil {
		log.WithError(err).Fatal("Error running daemon")
	}

	<-sigs
	daemon.Stop()
}
