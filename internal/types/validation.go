package types

// ServiceValidator defines the interface for validating service configurations
type ServiceValidator interface {
	ValidateServiceConfig(config *ServiceConfig) *ValidationResult
	AddExistingService(hostname string, config *ServiceConfig)
	RemoveExistingService(hostname string)
	GetExistingServices() map[string]*ServiceConfig
}
