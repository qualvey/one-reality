package main

import (
	"reflect"
	"testing"
)

func TestParseGlobalFlags(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantConfig   string
		wantForce    bool
		wantRemain   []string
	}{
		{
			name:       "no flags",
			args:       []string{"auto", "85.155.184.100"},
			wantConfig: "",
			wantForce:  false,
			wantRemain: []string{"auto", "85.155.184.100"},
		},
		{
			name:       "short force flag before subcmd",
			args:       []string{"-f", "auto", "85.155.184.100"},
			wantConfig: "",
			wantForce:  true,
			wantRemain: []string{"auto", "85.155.184.100"},
		},
		{
			name:       "long force flag after subcmd",
			args:       []string{"auto", "85.155.184.100", "--force"},
			wantConfig: "",
			wantForce:  true,
			wantRemain: []string{"auto", "85.155.184.100"},
		},
		{
			name:       "config and force flags combined",
			args:       []string{"-c", "my-conf.yaml", "--force", "serve", "--port", "8881"},
			wantConfig: "my-conf.yaml",
			wantForce:  true,
			wantRemain: []string{"serve", "--port", "8881"},
		},
		{
			name:       "config with equal sign",
			args:       []string{"--config=custom.yaml", "-f", "get", "1.1.1.1"},
			wantConfig: "custom.yaml",
			wantForce:  true,
			wantRemain: []string{"get", "1.1.1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConfig, gotForce, gotRemain := parseGlobalFlags(tt.args)
			if gotConfig != tt.wantConfig {
				t.Errorf("parseGlobalFlags() config = %v, want %v", gotConfig, tt.wantConfig)
			}
			if gotForce != tt.wantForce {
				t.Errorf("parseGlobalFlags() force = %v, want %v", gotForce, tt.wantForce)
			}
			if !reflect.DeepEqual(gotRemain, tt.wantRemain) {
				t.Errorf("parseGlobalFlags() remain = %v, want %v", gotRemain, tt.wantRemain)
			}
		})
	}
}
