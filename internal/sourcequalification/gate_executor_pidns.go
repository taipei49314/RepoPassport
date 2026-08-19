package sourcequalification

import "bytes"

// linuxStatusNSpidCount returns how many pid namespace identifiers appear in a
// /proc/self/status NSpid: line. The host pid namespace has one field; a nested
// unshare --pid namespace has two or more. Missing or empty NSpid is 0.

func linuxStatusNSpidCount(status []byte) int {
	const prefix = "NSpid:"
	for _, line := range bytes.Split(status, []byte{'\n'}) {
		if !bytes.HasPrefix(line, []byte(prefix)) {
			continue
		}
		return len(bytes.Fields(line[len(prefix):]))
	}
	return 0
}
