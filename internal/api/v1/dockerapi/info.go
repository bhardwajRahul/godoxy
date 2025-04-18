package dockerapi

import (
	"context"
	"net/http"
	"sort"

	"github.com/yusing/go-proxy/pkg/json"

	dockerSystem "github.com/docker/docker/api/types/system"
	"github.com/yusing/go-proxy/internal/utils/strutils"
	"github.com/yusing/go-proxy/pkg/gperr"
)

type dockerInfo dockerSystem.Info

func (d *dockerInfo) MarshalJSONTo(buf []byte) []byte {
	return json.MarshalTo(map[string]any{
		"name":    d.Name,
		"version": d.ServerVersion,
		"containers": map[string]int{
			"total":   d.Containers,
			"running": d.ContainersRunning,
			"paused":  d.ContainersPaused,
			"stopped": d.ContainersStopped,
		},
		"images": d.Images,
		"n_cpu":  d.NCPU,
		"memory": strutils.FormatByteSize(d.MemTotal),
	}, buf)
}

func DockerInfo(w http.ResponseWriter, r *http.Request) {
	serveHTTP[dockerInfo](w, r, GetDockerInfo)
}

func GetDockerInfo(ctx context.Context, dockerClients DockerClients) ([]dockerInfo, gperr.Error) {
	errs := gperr.NewBuilder("failed to get docker info")
	dockerInfos := make([]dockerInfo, len(dockerClients))

	i := 0
	for name, dockerClient := range dockerClients {
		info, err := dockerClient.Info(ctx)
		if err != nil {
			errs.Add(err)
			continue
		}
		info.Name = name
		dockerInfos[i] = dockerInfo(info)
		i++
	}

	sort.Slice(dockerInfos, func(i, j int) bool {
		return dockerInfos[i].Name < dockerInfos[j].Name
	})
	return dockerInfos, errs.Error()
}
