package ztagents

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/devhatro/zero-trust-proxy/internal/common"
)

type Agent struct {
	ID               string
	Conn             net.Conn
	writeMu          sync.Mutex
	readMu           sync.Mutex
	ResponseHandlers map[string]func(*common.Message)
	Services         map[string]*common.ServiceConfig
	Registered       bool
	mu               sync.RWMutex
}

func NewAgent(id string, conn net.Conn) *Agent {
	return &Agent{
		ID:               id,
		Conn:             conn,
		ResponseHandlers: make(map[string]func(*common.Message)),
		Services:         make(map[string]*common.ServiceConfig),
	}
}

func (a *Agent) SetResponseHandler(msgID string, handler func(*common.Message)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ResponseHandlers[msgID] = handler
}

func (a *Agent) TakeResponseHandler(msgID string) (func(*common.Message), bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h, ok := a.ResponseHandlers[msgID]
	if ok {
		delete(a.ResponseHandlers, msgID)
	}
	return h, ok
}

// GetResponseHandler returns the handler for msgID without removing it. Used on
// the dispatch path where the caller (router) owns cleanup via a defer — this
// allows multi-message flows like download streaming to reach the same handler.
func (a *Agent) GetResponseHandler(msgID string) (func(*common.Message), bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	h, ok := a.ResponseHandlers[msgID]
	return h, ok
}

func (a *Agent) SendMessage(msg *common.Message) error {
	if a.Conn == nil {
		return fmt.Errorf("agent not connected")
	}

	a.writeMu.Lock()
	defer a.writeMu.Unlock()

	timeoutConfig := common.DefaultTimeouts()
	writeTimeout := common.CalculateWriteTimeout(msg, timeoutConfig)

	if err := a.Conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	return json.NewEncoder(a.Conn).Encode(msg)
}
