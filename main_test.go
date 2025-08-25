package main

import (
	"reflect"
	"testing"
)

func TestSplitWithEscapes(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		delimiter string
		expected  []string
	}{
		{
			name:      "simple comma split",
			input:     "a,b,c",
			delimiter: ",",
			expected:  []string{"a", "b", "c"},
		},
		{
			name:      "escaped comma",
			input:     "a,b\\,c,d",
			delimiter: ",",
			expected:  []string{"a", "b,c", "d"},
		},
		{
			name:      "email with escaped comma",
			input:     "user@domain.com\\,backup,*@example.org",
			delimiter: ",",
			expected:  []string{"user@domain.com,backup", "*@example.org"},
		},
		{
			name:      "glob pattern with escaped comma",
			input:     "admin.*@company\\,inc.*,*@example.com",
			delimiter: ",",
			expected:  []string{"admin.*@company,inc.*", "*@example.com"},
		},
		{
			name:      "empty string",
			input:     "",
			delimiter: ",",
			expected:  []string{},
		},
		{
			name:      "single item",
			input:     "single",
			delimiter: ",",
			expected:  []string{"single"},
		},
		{
			name:      "no escapes needed",
			input:     "user1@example.com,user2@test.org",
			delimiter: ",",
			expected:  []string{"user1@example.com", "user2@test.org"},
		},
		{
			name:      "multiple escaped commas",
			input:     "a\\,b\\,c,d,e\\,f",
			delimiter: ",",
			expected:  []string{"a,b,c", "d", "e,f"},
		},
		{
			name:      "whitespace trimming",
			input:     "a , b\\,c , d",
			delimiter: ",",
			expected:  []string{"a", "b,c", "d"},
		},
		{
			name:      "different delimiter",
			input:     "a;b\\;c;d",
			delimiter: ";",
			expected:  []string{"a", "b;c", "d"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := splitWithEscapes(tc.input, tc.delimiter)

			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestGetEnvWithDefault(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		def      string
		expected string
		setEnv   bool
		envValue string
	}{
		{
			name:     "env var not set",
			key:      "TEST_KEY_NOT_SET",
			def:      "default_value",
			expected: "default_value",
			setEnv:   false,
		},
		{
			name:     "env var set",
			key:      "TEST_KEY_SET",
			def:      "default_value",
			expected: "env_value",
			setEnv:   true,
			envValue: "env_value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			if tc.setEnv {
				t.Setenv(tc.key, tc.envValue)
			}

			// Test
			result := getEnvWithDefault(tc.key, tc.def)

			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestGetEnvBoolWithDefault(t *testing.T) {
	testCases := []struct {
		name     string
		key      string
		def      bool
		expected bool
		setEnv   bool
		envValue string
	}{
		{
			name:     "env var not set - default false",
			key:      "TEST_BOOL_NOT_SET",
			def:      false,
			expected: false,
			setEnv:   false,
		},
		{
			name:     "env var not set - default true",
			key:      "TEST_BOOL_NOT_SET2",
			def:      true,
			expected: true,
			setEnv:   false,
		},
		{
			name:     "env var set to 'true'",
			key:      "TEST_BOOL_TRUE",
			def:      false,
			expected: true,
			setEnv:   true,
			envValue: "true",
		},
		{
			name:     "env var set to 'TRUE'",
			key:      "TEST_BOOL_TRUE_UPPER",
			def:      false,
			expected: true,
			setEnv:   true,
			envValue: "TRUE",
		},
		{
			name:     "env var set to '1'",
			key:      "TEST_BOOL_ONE",
			def:      false,
			expected: true,
			setEnv:   true,
			envValue: "1",
		},
		{
			name:     "env var set to 'false'",
			key:      "TEST_BOOL_FALSE",
			def:      true,
			expected: false,
			setEnv:   true,
			envValue: "false",
		},
		{
			name:     "env var set to '0'",
			key:      "TEST_BOOL_ZERO",
			def:      true,
			expected: false,
			setEnv:   true,
			envValue: "0",
		},
		{
			name:     "env var set to other value",
			key:      "TEST_BOOL_OTHER",
			def:      true,
			expected: false,
			setEnv:   true,
			envValue: "other",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			if tc.setEnv {
				t.Setenv(tc.key, tc.envValue)
			}

			// Test
			result := getEnvBoolWithDefault(tc.key, tc.def)

			if result != tc.expected {
				t.Errorf("Expected %t, got %t", tc.expected, result)
			}
		})
	}
}
