package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// buildPaymentCardNotes
// ---------------------------------------------------------------------------

func TestBuildPaymentCardNotes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input CreateInput
		want  string
	}{
		{
			name: "all fields",
			input: CreateInput{
				CardholderName: "Jane Doe",
				CardType:       "Visa",
				CardNumber:     "4111111111111111",
				SecurityCode:   "999",
				StartDate:      "01/2022",
				ExpirationDate: "01/2027",
				Notes:          "personal card",
			},
			want: "NoteType:Credit Card\nLanguage:Jane Doe\nType:Visa\nNumber:4111111111111111\nSecurity Code:999\nStart Date:01/2022\nExpiration Date:01/2027\nNotes:personal card",
		},
		{
			name:  "no optional fields",
			input: CreateInput{},
			want:  "NoteType:Credit Card",
		},
		{
			name: "partial fields: name and number only",
			input: CreateInput{
				CardholderName: "Bob",
				CardNumber:     "1234",
			},
			want: "NoteType:Credit Card\nLanguage:Bob\nNumber:1234",
		},
		{
			name: "only notes",
			input: CreateInput{
				Notes: "important note",
			},
			want: "NoteType:Credit Card\nNotes:important note",
		},
		{
			name: "only card type and security code",
			input: CreateInput{
				CardType:     "Mastercard",
				SecurityCode: "321",
			},
			want: "NoteType:Credit Card\nType:Mastercard\nSecurity Code:321",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildPaymentCardNotes(tc.input)
			if got != tc.want {
				t.Errorf("buildPaymentCardNotes()\n  got:  %q\n  want: %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildPaymentCardNotes always starts with NoteType header
// ---------------------------------------------------------------------------

func TestBuildPaymentCardNotes_AlwaysIncludesNoteType(t *testing.T) {
	t.Parallel()

	inputs := []CreateInput{
		{},
		{CardholderName: "X"},
		{CardNumber: "1", SecurityCode: "2", ExpirationDate: "12/2030"},
	}

	for i, input := range inputs {
		got := buildPaymentCardNotes(input)
		if len(got) < len("NoteType:Credit Card") {
			t.Errorf("case %d: result too short: %q", i, got)
			continue
		}
		prefix := got[:len("NoteType:Credit Card")]
		if prefix != "NoteType:Credit Card" {
			t.Errorf("case %d: expected NoteType header, got prefix %q", i, prefix)
		}
	}
}

// ---------------------------------------------------------------------------
// extractBearerToken
// ---------------------------------------------------------------------------

func TestExtractBearerToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		authValue string
		want      string
	}{
		{
			name:      "valid bearer token",
			authValue: "Bearer abc123xyz",
			want:      "abc123xyz",
		},
		{
			name:      "empty header",
			authValue: "",
			want:      "",
		},
		{
			name:      "wrong scheme (Basic)",
			authValue: "Basic dXNlcjpwYXNz",
			want:      "",
		},
		{
			name:      "bearer lowercase (should not match)",
			authValue: "bearer abc123",
			want:      "",
		},
		{
			name:      "Bearer with no token value",
			authValue: "Bearer ",
			want:      "",
		},
		{
			name:      "Bearer with spaces in token",
			authValue: "Bearer token with spaces",
			want:      "token with spaces",
		},
		{
			name:      "missing space after Bearer",
			authValue: "Bearertoken",
			want:      "",
		},
		{
			name:      "long JWT-like token",
			authValue: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			want:      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.authValue != "" {
				r.Header.Set("Authorization", tc.authValue)
			}
			got := extractBearerToken(r)
			if got != tc.want {
				t.Errorf("extractBearerToken(%q) = %q, want %q", tc.authValue, got, tc.want)
			}
		})
	}
}
