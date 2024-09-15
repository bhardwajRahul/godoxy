package route

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	E "github.com/yusing/go-proxy/error"
	P "github.com/yusing/go-proxy/proxy"
)

type StreamRoute struct {
	*P.StreamEntry
	StreamImpl `json:"-"`

	wg      sync.WaitGroup
	stopCh  chan struct{}
	connCh  chan any
	started atomic.Bool
	l       logrus.FieldLogger
}

type StreamImpl interface {
	Setup() error
	Accept() (any, error)
	Handle(any) error
	CloseListeners()
}

func NewStreamRoute(entry *P.StreamEntry) (*StreamRoute, E.NestedError) {
	// TODO: support non-coherent scheme
	if !entry.Scheme.IsCoherent() {
		return nil, E.Unsupported("scheme", fmt.Sprintf("%v -> %v", entry.Scheme.ListeningScheme, entry.Scheme.ProxyScheme))
	}
	base := &StreamRoute{
		StreamEntry: entry,
		wg:          sync.WaitGroup{},
		stopCh:      make(chan struct{}, 1),
		connCh:      make(chan any),
	}
	if entry.Scheme.ListeningScheme.IsTCP() {
		base.StreamImpl = NewTCPRoute(base)
	} else {
		base.StreamImpl = NewUDPRoute(base)
	}
	base.l = logrus.WithField("route", base.StreamImpl)
	return base, E.Nil()
}

func (r *StreamRoute) String() string {
	return fmt.Sprintf("%s-stream: %s", r.Scheme, r.Alias)
}

func (r *StreamRoute) Start() E.NestedError {
	if r.started.Load() {
		return E.Invalid("state", "already started")
	}
	r.wg.Wait()
	if err := r.Setup(); err != nil {
		return E.Failure("setup").With(err)
	}
	r.started.Store(true)
	r.wg.Add(2)
	go r.grAcceptConnections()
	go r.grHandleConnections()
	return E.Nil()
}

func (r *StreamRoute) Stop() E.NestedError {
	if !r.started.Load() {
		return E.Invalid("state", "not started")
	}
	l := r.l
	close(r.stopCh)
	r.CloseListeners()

	done := make(chan struct{}, 1)
	go func() {
		r.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		l.Info("stopped listening")
	case <-time.After(streamStopListenTimeout):
		l.Error("timed out waiting for connections")
	}
	return E.Nil()
}

func (r *StreamRoute) grAcceptConnections() {
	defer r.wg.Done()

	for {
		select {
		case <-r.stopCh:
			return
		default:
			conn, err := r.Accept()
			if err != nil {
				select {
				case <-r.stopCh:
					return
				default:
					r.l.Error(err)
					continue
				}
			}
			r.connCh <- conn
		}
	}
}

func (r *StreamRoute) grHandleConnections() {
	defer r.wg.Done()

	for {
		select {
		case <-r.stopCh:
			return
		case conn := <-r.connCh:
			go func() {
				err := r.Handle(conn)
				if err != nil {
					r.l.Error(err)
				}
			}()
		}
	}
}
