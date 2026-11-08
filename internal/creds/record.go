package creds

import (
	"encoding/json"
	"fmt"
)

// RecordVersion is the format version written into every record.
const RecordVersion = 1

// Record is one account's stored session, saved as a single item.
type Record struct {
	V            int    `json:"v"`
	ClientID     string `json:"client_id,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	AccessExpiry int64  `json:"access_expiry,omitempty"` // Unix seconds
	Identity     string `json:"identity,omitempty"`      // "Name <email>"
}

// SignedIn reports whether the record holds a session (logout keeps only
// the client id).
func (r Record) SignedIn() bool { return r.RefreshToken != "" }

func encodeRecord(r Record) ([]byte, error) {
	r.V = RecordVersion
	return json.Marshal(r)
}

// decodeVersioned unmarshals b into out after checking its "v": newer
// versions are KindNewerFormat, anything unparsable or unversioned is
// KindCorrupt. The returned *Error has no account/op; callers fill them in.
func decodeVersioned(b []byte, current int, out any) error {
	var probe struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return &Error{Kind: KindCorrupt, Detail: "not valid JSON", Err: err}
	}
	if probe.V > current {
		return &Error{Kind: KindNewerFormat, Detail: fmt.Sprintf("format %d, this build reads %d", probe.V, current)}
	}
	if probe.V < 1 {
		return &Error{Kind: KindCorrupt, Detail: "no format version"}
	}
	if err := json.Unmarshal(b, out); err != nil {
		return &Error{Kind: KindCorrupt, Detail: "unexpected contents", Err: err}
	}
	return nil
}

func decodeRecord(b []byte) (Record, error) {
	var r Record
	if err := decodeVersioned(b, RecordVersion, &r); err != nil {
		return Record{}, err
	}
	return r, nil
}
