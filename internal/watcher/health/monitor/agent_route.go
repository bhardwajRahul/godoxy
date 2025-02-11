package monitor

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	agentPkg "github.com/yusing/go-proxy/agent/pkg/agent"
	"github.com/yusing/go-proxy/internal/net/types"
	"github.com/yusing/go-proxy/internal/watcher/health"
)

type (
	AgentRouteMonior struct {
		agent       *agentPkg.AgentConfig
		endpointURL string
		*monitor
	}
	AgentCheckHealthTarget struct {
		Scheme string
		Host   string
		Path   string
	}
)

func AgentTargetFromURL(url *types.URL) *AgentCheckHealthTarget {
	return &AgentCheckHealthTarget{
		Scheme: url.Scheme,
		Host:   url.Host,
		Path:   url.Path,
	}
}

func (target *AgentCheckHealthTarget) buildQuery() string {
	query := make(url.Values, 3)
	query.Set("scheme", target.Scheme)
	query.Set("host", target.Host)
	query.Set("path", target.Path)
	return query.Encode()
}

func (target *AgentCheckHealthTarget) displayURL() *types.URL {
	return types.NewURL(&url.URL{
		Scheme: target.Scheme,
		Host:   target.Host,
		Path:   target.Path,
	})
}

func NewAgentRouteMonitor(agent *agentPkg.AgentConfig, config *health.HealthCheckConfig, target *AgentCheckHealthTarget) *AgentRouteMonior {
	mon := &AgentRouteMonior{
		agent:       agent,
		endpointURL: agentPkg.EndpointHealth + "?" + target.buildQuery(),
	}
	mon.monitor = newMonitor(target.displayURL(), config, mon.CheckHealth)
	return mon
}

func (mon *AgentRouteMonior) CheckHealth() (result *health.HealthCheckResult, err error) {
	result = new(health.HealthCheckResult)
	ctx, cancel := mon.ContextWithTimeout("timeout querying agent")
	defer cancel()
	data, status, err := mon.agent.Fetch(ctx, mon.endpointURL)
	if err != nil {
		return result, err
	}
	switch status {
	case http.StatusOK:
		err = json.Unmarshal(data, result)
	default:
		err = errors.New(string(data))
	}
	return
}
