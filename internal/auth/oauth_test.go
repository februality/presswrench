package auth

import "testing"

func TestDecodeOAuthError(t *testing.T) {
	cases := []struct {
		name, body, code, desc string
	}{
		{"rfc", `{"error":"invalid_grant","error_description":"spent"}`, "invalid_grant", "spent"},
		{"pressable", `{"message":"invalid_grant","data":null,"errors":["User credentials or grant type are invalid"]}`, "invalid_grant", "User credentials or grant type are invalid"},
		{"pressable client", `{"message":"invalid_client","errors":[]}`, "invalid_client", ""},
		{"other message", `{"message":"Server exploded"}`, "http_error", `{"message":"Server exploded"}`},
		{"not json", `<html>502</html>`, "http_error", `<html>502</html>`},
	}
	for _, c := range cases {
		oe := decodeOAuthError(400, []byte(c.body))
		if oe.Status != 400 || oe.Code != c.code || oe.Description != c.desc {
			t.Errorf("%s: got %+v, want code %q desc %q", c.name, oe, c.code, c.desc)
		}
	}
}
