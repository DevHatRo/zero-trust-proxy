package ztagents

import "github.com/devhatro/zero-trust-proxy/internal/common"

// NewTestApp returns an App with an initialized runtime and no listener.
// Intended for tests in other packages that need to drive the module in-process.
func NewTestApp() *App {
	return &App{rt: &runtime{
		registry:  newRegistry(),
		wsManager: common.NewWebSocketManager(),
	}}
}

// AddAgent inserts an agent into the app's registry. Intended for tests.
func (a *App) AddAgent(agent *Agent) {
	a.rt.registry.add(agent)
}

// DispatchAgentMessageForTest runs the app's agent message handler synchronously.
// Intended for tests that need to exercise the agent→server message flow without
// a real TCP connection.
func (a *App) DispatchAgentMessageForTest(agent *Agent, msg *common.Message) error {
	return a.handleAgentMessage(agent, msg)
}
