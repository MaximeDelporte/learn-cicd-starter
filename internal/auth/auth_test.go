package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestCorrectAPIKey(t *testing.T) {
	header := http.Header{}
	header.Add("Authorization", "ApiKey 123")

	got, _ := GetAPIKey(header)
	want := "123"

	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestNoAuthHeaderError(t *testing.T) {
	header := http.Header{}
	header.Add("key", "value")

	_, got := GetAPIKey(header)
	want := errors.New("no authorization header included")

	if got.Error() != want.Error() {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestMalformedAuthHeaderError(t *testing.T) {
	header := http.Header{}
	header.Add("Authorization", "WrongValue 1 2 3")

	_, got := GetAPIKey(header)
	want := errors.New("malformed authorization header")

	if got.Error() != want.Error() {
		t.Errorf("got %q want %q", got, want)
	}
}
