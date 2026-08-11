package sourcequalification

import (
	"bytes"
	"errors"
	"reflect"

	"github.com/taipei49314/RepoPassport/internal/canonicaljson"
)

func marshalCanonicalReceipt(document qualificationReceipt, lane Lane) ([]byte, error) {
	if document.Execution.RawLogsPublished {
		return nil, errors.New("source qualification receipt cannot publish raw logs")
	}
	raw, err := canonicaljson.Marshal(document)
	if err != nil || len(raw) == 0 || len(raw) > receiptMaxBytes {
		return nil, errors.New("source qualification receipt could not be encoded")
	}
	parsed, err := parseCanonicalReceipt(raw, lane)
	if err != nil || !reflect.DeepEqual(parsed, document) {
		return nil, errors.New("source qualification receipt is not a valid canonical document")
	}
	reencoded, err := canonicaljson.Marshal(parsed)
	if err != nil || !bytes.Equal(reencoded, raw) {
		return nil, errors.New("source qualification receipt canonical replay failed")
	}
	return raw, nil
}
