package main

import (
	"os"

	"github.com/yusing/go-proxy/agent/pkg/agent"
	"github.com/yusing/go-proxy/agent/pkg/env"
	"github.com/yusing/go-proxy/agent/pkg/server"
	"github.com/yusing/go-proxy/internal/logging"
	"github.com/yusing/go-proxy/internal/logging/memlogger"
	"github.com/yusing/go-proxy/internal/metrics/systeminfo"
	"github.com/yusing/go-proxy/internal/task"
	"github.com/yusing/go-proxy/pkg"
	"github.com/yusing/go-proxy/pkg/gperr"
)

func main() {
	logging.InitLogger(os.Stderr, memlogger.GetMemLogger())

	ca := &agent.PEMPair{}
	err := ca.Load(env.AgentCACert)
	if err != nil {
		gperr.LogFatal("init CA error", err)
	}
	caCert, err := ca.ToTLSCert()
	if err != nil {
		gperr.LogFatal("init CA error", err)
	}

	srv := &agent.PEMPair{}
	srv.Load(env.AgentSSLCert)
	if err != nil {
		gperr.LogFatal("init SSL error", err)
	}
	srvCert, err := srv.ToTLSCert()
	if err != nil {
		gperr.LogFatal("init SSL error", err)
	}

	logging.Info().Msgf("GoDoxy Agent version %s", pkg.GetVersion())
	logging.Info().Msgf("Agent name: %s", env.AgentName)
	logging.Info().Msgf("Agent port: %d", env.AgentPort)

	logging.Info().Msg(`
Tips:
1. To change the agent name, you can set the AGENT_NAME environment variable.
2. To change the agent port, you can set the AGENT_PORT environment variable.
`)

	t := task.RootTask("agent", false)
	opts := server.Options{
		CACert:     caCert,
		ServerCert: srvCert,
		Port:       env.AgentPort,
	}

	server.StartAgentServer(t, opts)
	systeminfo.Poller.Start()

	task.WaitExit(3)
}
