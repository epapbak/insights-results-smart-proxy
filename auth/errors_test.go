package auth_test

import (
	"testing"

	"github.com/RedHatInsights/insights-results-smart-proxy/auth"
	"github.com/stretchr/testify/assert"
)

// TestAuthenticationError checks the method Error() for data structure
// AuthenticationError
func TestAuthenticationError(t *testing.T) {
	// expected error value
	const expected = "errorMessage"

	// construct an instance of error interface
	err := auth.AuthenticationError{
		ErrString: "errorMessage"}

	// check if error value is correct
	assert.Equal(t, err.Error(), expected)
}
