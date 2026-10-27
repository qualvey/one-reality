package types

import "testing"

func TestClassifyStatusCodeRejectsNotFound(t *testing.T) {
	if got := ClassifyStatusCode(404, true); got != StatusCodeCategoryExcluded {
		t.Fatalf("ClassifyStatusCode(404, true) = %q, want %q", got, StatusCodeCategoryExcluded)
	}
}

func TestClassifyStatusCodeAcceptsPermanentRedirect(t *testing.T) {
	if got := ClassifyStatusCode(301, true); got != StatusCodeCategorySafe {
		t.Fatalf("ClassifyStatusCode(301, true) = %q, want %q", got, StatusCodeCategorySafe)
	}
}
