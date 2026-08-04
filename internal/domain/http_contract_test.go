package domain

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseAlphaHTTPURLBoundaries(t *testing.T) {
	prefix := "http://127.0.0.1:80/"
	exact := prefix + strings.Repeat("a", AlphaHTTPMaxURLBytes-len(prefix))
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "2048 bytes", value: exact},
		{name: "2049 bytes", value: exact + "a", wantErr: true},
		{name: "explicit port 80", value: "http://127.0.0.1:80/"},
		{name: "leading zero port", value: "http://127.0.0.1:080/", wantErr: true},
		{name: "raw non ASCII", value: "http://127.0.0.1:80/界", wantErr: true},
		{name: "encoded non ASCII", value: "http://127.0.0.1:80/%E7%95%8C"},
		{name: "literal dot segment", value: "http://127.0.0.1:80/a/../b", wantErr: true},
		{name: "encoded dot segment", value: "http://127.0.0.1:80/a/%2E%2E/b", wantErr: true},
		{name: "backslash", value: `http://127.0.0.1:80/a\b`, wantErr: true},
		{name: "unsafe query character", value: "http://127.0.0.1:80/?value={x}", wantErr: true},
		{name: "malformed query escape", value: "http://127.0.0.1:80/?value=%zz", wantErr: true},
		{name: "encoded query", value: "http://127.0.0.1:80/?value=%7Bok%7D"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, port, err := ParseAlphaHTTPURL(test.value)
			if test.wantErr && err == nil {
				t.Fatalf("ParseAlphaHTTPURL(%q) unexpectedly succeeded", test.value)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("ParseAlphaHTTPURL(%q): %v", test.value, err)
			}
			if !test.wantErr && port != 80 {
				t.Fatalf("ParseAlphaHTTPURL(%q) port = %d, want 80", test.value, port)
			}
		})
	}
}

func TestParseAlphaHTTPDurationRequiresWholeMilliseconds(t *testing.T) {
	for _, value := range []string{"1ns", "1.5ms", "0ms", "2m1ms"} {
		if _, err := ParseAlphaHTTPDuration(value, AlphaHTTPMaxReadinessTime); err == nil {
			t.Fatalf("ParseAlphaHTTPDuration(%q) unexpectedly succeeded", value)
		}
	}
	for _, value := range []string{"1ms", "1500ms", "1.5s", "2m"} {
		if _, err := ParseAlphaHTTPDuration(value, AlphaHTTPMaxReadinessTime); err != nil {
			t.Fatalf("ParseAlphaHTTPDuration(%q): %v", value, err)
		}
	}
	if _, err := ParseAlphaHTTPDuration("1h", 0); err != nil {
		t.Fatalf("ParseAlphaHTTPDuration(1h) without maximum: %v", err)
	}
}

func TestValidateAlphaHTTPHeadersEffectiveBoundaries(t *testing.T) {
	headers63 := make(map[string]string, 63)
	for index := 0; index < 63; index++ {
		headers63[fmt.Sprintf("x-%02d", index)] = "ok"
	}
	if err := ValidateAlphaHTTPHeaders(headers63, true); err != nil {
		t.Fatalf("63 declared plus automatic JSON Content-Type: %v", err)
	}
	headers64 := make(map[string]string, 64)
	for name, value := range headers63 {
		headers64[name] = value
	}
	headers64["x-63"] = "ok"
	if err := ValidateAlphaHTTPHeaders(headers64, true); err == nil {
		t.Fatal("64 declared plus automatic JSON Content-Type unexpectedly succeeded")
	}
	headers64[AlphaHTTPContentTypeName] = AlphaHTTPJSONContentType
	delete(headers64, "x-63")
	if err := ValidateAlphaHTTPHeaders(headers64, true); err != nil {
		t.Fatalf("64 effective headers with declared Content-Type: %v", err)
	}

	aggregate := map[string]string{
		AlphaHTTPContentTypeName: AlphaHTTPJSONContentType,
	}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		aggregate[name] = strings.Repeat("x", AlphaHTTPMaxHeaderValueBytes)
	}
	aggregate["h"] = strings.Repeat("x", 8120)
	if err := ValidateAlphaHTTPHeaders(aggregate, true); err != nil {
		t.Fatalf("exact 65536-byte aggregate: %v", err)
	}
	aggregate["h"] += "x"
	if err := ValidateAlphaHTTPHeaders(aggregate, true); err == nil {
		t.Fatal("65537-byte aggregate unexpectedly succeeded")
	}

	if err := ValidateAlphaHTTPHeaders(
		map[string]string{"x-test": "界"},
		false,
	); err == nil {
		t.Fatal("non-ASCII header value unexpectedly succeeded")
	}
}

func TestValidateAlphaHTTPOutputPathUTF8ByteBoundary(t *testing.T) {
	exact := "/outputs/" + strings.Repeat("界", 1362) + "x"
	if got := len([]byte(exact)); got != AlphaHTTPMaxOutputPathBytes {
		t.Fatalf("test path bytes = %d, want %d", got, AlphaHTTPMaxOutputPathBytes)
	}
	if err := ValidateAlphaHTTPOutputPath(exact); err != nil {
		t.Fatalf("4096-byte Unicode output path: %v", err)
	}
	if err := ValidateAlphaHTTPOutputPath(exact + "x"); err == nil {
		t.Fatal("4097-byte Unicode output path unexpectedly succeeded")
	}
}
