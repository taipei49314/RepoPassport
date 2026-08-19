package sourcequalification

import (
	"bytes"
	"strings"
)

const (
	linuxPidNamespaceEnvironmentName  = "REPOPASS_LINUX_PID_NAMESPACE"
	linuxPidNamespaceEnvironmentValue = "1"
	linuxPidNamespaceEnvironment      = linuxPidNamespaceEnvironmentName + "=" + linuxPidNamespaceEnvironmentValue
)

func linuxIsolationProcessEnvironment(environment []string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, item := range environment {
		name, _, found := strings.Cut(item, "=")
		if found && name == linuxPidNamespaceEnvironmentName {
			continue
		}
		result = append(result, item)
	}
	return append(result, linuxPidNamespaceEnvironment)
}

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
