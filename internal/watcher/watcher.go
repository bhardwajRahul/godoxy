package watcher

import (
	"context"

	"github.com/yusing/go-proxy/internal/watcher/events"
	"github.com/yusing/go-proxy/pkg/gperr"
)

type Event = events.Event

type Watcher interface {
	Events(ctx context.Context) (<-chan Event, <-chan gperr.Error)
}
