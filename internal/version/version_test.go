package version

import (
	"testing"
)

func TestVersionGetters(t *testing.T) {
	if GetAppName() == "" {
		t.Errorf("GetAppName() returned empty string")
	}
	if GetVersion() == "" {
		t.Errorf("GetVersion() returned empty string")
	}
	if GetCommit() == "" {
		t.Errorf("GetCommit() returned empty string")
	}
	if GetBuildTime() == "" {
		t.Errorf("GetBuildTime() returned empty string")
	}
}

func TestDefaultAppName(t *testing.T) {
	if AppName == "" {
		t.Errorf("AppName should not be empty")
	}
}
