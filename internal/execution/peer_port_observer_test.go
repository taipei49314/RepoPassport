package execution

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/repopass/repopass/internal/domain"
	"github.com/repopass/repopass/internal/privacy"
	"github.com/repopass/repopass/internal/runtimepolicy"
)

func TestPeerPortProcNetTCPParserIsBoundedAndStrict(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid timeout inode\n"
	ipv4Row := "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1\n"
	ignoredRow := "   1: 00000000:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000 1000 0 2\n"
	endpoints, err := parseProcNetTCPTable(
		[]byte(header+ipv4Row+ignoredRow),
		false,
	)
	if err != nil {
		t.Fatalf("valid IPv4 table rejected: %v", err)
	}
	if !slices.Equal(endpoints, []string{"127.0.0.1:8080/tcp"}) {
		t.Fatalf("unexpected IPv4 listeners: %#v", endpoints)
	}

	ipv6Row := "   0: 00000000000000000000000001000000:2328 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 3\n"
	endpoints, err = parseProcNetTCPTable(
		[]byte(header+ipv6Row),
		true,
	)
	if err != nil {
		t.Fatalf("valid IPv6 table rejected: %v", err)
	}
	if !slices.Equal(endpoints, []string{"[::1]:9000/tcp"}) {
		t.Fatalf("unexpected IPv6 listeners: %#v", endpoints)
	}

	tooManyRows := header
	for index := 1; index <= peerPortEndpointLimit+1; index++ {
		tooManyRows += fmt.Sprintf(
			" %d: 0100007F:%04X 00000000:0000 0A x\n",
			index,
			index,
		)
	}
	for name, raw := range map[string][]byte{
		"empty":          nil,
		"missing-header": []byte("not a proc table\n"),
		"empty-row":      []byte(header + "\n"),
		"lowercase": []byte(
			header +
				" 0: 0100007F:1F90 00000000:0000 0a x\n",
		),
		"bad-address": []byte(
			header +
				" 0: 0100007G:1F90 00000000:0000 0A x\n",
		),
		"zero-port": []byte(
			header +
				" 0: 0100007F:0000 00000000:0000 0A x\n",
		),
		"duplicate": []byte(header + ipv4Row + ipv4Row),
		"invalid-utf8": append(
			[]byte(header),
			[]byte{0xff, '\n'}...,
		),
		"oversize":       []byte(strings.Repeat("x", (64<<10)+1)),
		"endpoint-bound": []byte(tooManyRows),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseProcNetTCPTable(raw, false); err == nil {
				t.Fatal("malformed proc TCP table was accepted")
			}
		})
	}
}

func TestPeerPortProfileGatingRequiresOneSealedHTTPService(t *testing.T) {
	valid := testPeerPortPlan()
	endpoints, err := declaredPeerPortEndpoints(valid)
	if err != nil {
		t.Fatalf("valid HTTP profile rejected: %v", err)
	}
	if !slices.Equal(endpoints, []string{"127.0.0.1:8080/tcp"}) {
		t.Fatalf("unexpected declared endpoints: %#v", endpoints)
	}

	requirementCases := []domain.ResolvedPlan{
		{ObserverSet: []string{"port-listen"}},
		{ObserverVersions: map[string]string{"port-listen": "0.2.0"}},
		{RequiredRunnerFeatures: []string{"port-listen-observation"}},
		{RequiredRunnerFeatures: []string{"observer:port-listen"}},
	}
	for index, plan := range requirementCases {
		if !planRequiresPortObservation(plan) {
			t.Fatalf("port observer requirement case %d was missed", index)
		}
	}
	if planRequiresPortObservation(domain.ResolvedPlan{}) {
		t.Fatal("port observer was required without a declared requirement")
	}

	mutations := map[string]func(*domain.ResolvedPlan){
		"missing-journey": func(plan *domain.ResolvedPlan) {
			plan.HTTPJourney = nil
		},
		"wrong-driver": func(plan *domain.ResolvedPlan) {
			plan.JourneyDriver = "argv"
		},
		"multiple-listeners": func(plan *domain.ResolvedPlan) {
			capability := plan.Capabilities[domain.PhaseRun]
			capability.Ports.Listen = append(
				capability.Ports.Listen,
				domain.PortBinding{
					Host:     "127.0.0.1",
					Port:     8081,
					Protocol: "tcp",
				},
			)
			plan.Capabilities[domain.PhaseRun] = capability
		},
		"non-loopback": func(plan *domain.ResolvedPlan) {
			capability := plan.Capabilities[domain.PhaseRun]
			capability.Ports.Listen[0].Host = "0.0.0.0"
			plan.Capabilities[domain.PhaseRun] = capability
		},
		"udp": func(plan *domain.ResolvedPlan) {
			capability := plan.Capabilities[domain.PhaseRun]
			capability.Ports.Listen[0].Protocol = "udp"
			plan.Capabilities[domain.PhaseRun] = capability
		},
		"unsupported-runtime": func(plan *domain.ResolvedPlan) {
			plan.RuntimeAdapter = "ruby"
		},
		"missing-signal": func(plan *domain.ResolvedPlan) {
			plan.Commands = plan.Commands[:1]
		},
		"readiness-port-mismatch": func(plan *domain.ResolvedPlan) {
			plan.Commands[0].Readiness.URL =
				"http://127.0.0.1:8081/ready"
		},
		"service-id-mismatch": func(plan *domain.ResolvedPlan) {
			plan.HTTPJourney.ServiceID = "other"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			plan := testPeerPortPlan()
			mutate(&plan)
			if _, err := declaredPeerPortEndpoints(plan); err == nil {
				t.Fatal("unsupported port observer profile was accepted")
			}
		})
	}
}

func TestPeerPortFramesFailClosed(t *testing.T) {
	token := strings.Repeat("a", 64)
	sessionDigest := peerPortSessionDigest(token)
	adapter := "node-proc-net-tcp-linux"
	namespaces := testPeerPortNamespaces("100", "101", "102", "103", "104")
	ready := testPeerPortReadyJSON(t, sessionDigest, adapter, namespaces)
	decodedReady, err := decodePeerPortReadyFrame(
		ready,
		sessionDigest,
		adapter,
	)
	if err != nil || decodedReady.Namespaces != namespaces {
		t.Fatalf("valid READY frame rejected: %#v, %v", decodedReady, err)
	}

	var readyValue map[string]any
	if err := json.Unmarshal(ready, &readyValue); err != nil {
		t.Fatal(err)
	}
	readyMutations := map[string]func(map[string]any){
		"unknown": func(value map[string]any) {
			value["extra"] = true
		},
		"missing": func(value map[string]any) {
			delete(value, "uid")
		},
		"short-cap-eff": func(value map[string]any) {
			value["capEff"] = "00000000"
		},
		"malformed-cap-eff": func(value map[string]any) {
			value["capEff"] = "000000000000000g"
		},
		"wrong-session": func(value map[string]any) {
			value["sessionDigest"] =
				"sha256:" + strings.Repeat("b", 64)
		},
		"not-initialized": func(value map[string]any) {
			value["initialSampleComplete"] = false
		},
	}
	for name, mutate := range readyMutations {
		t.Run("ready-"+name, func(t *testing.T) {
			copied := clonePeerPortJSONMap(readyValue)
			mutate(copied)
			raw, err := json.Marshal(copied)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodePeerPortReadyFrame(
				raw,
				sessionDigest,
				adapter,
			); err == nil {
				t.Fatal("invalid READY frame was accepted")
			}
		})
	}
	duplicateReady := strings.Replace(
		string(ready),
		`"type":"ready"`,
		`"type":"ready","type":"ready"`,
		1,
	)
	for name, raw := range map[string][]byte{
		"duplicate": []byte(duplicateReady),
		"trailing":  append(append([]byte(nil), ready...), []byte(`{}`)...),
		"invalid-utf8": {
			'{', '"', 'x', '"', ':', '"', 0xff, '"', '}',
		},
	} {
		t.Run("ready-"+name, func(t *testing.T) {
			if _, err := decodePeerPortReadyFrame(
				raw,
				sessionDigest,
				adapter,
			); err == nil {
				t.Fatal("invalid READY transport was accepted")
			}
		})
	}

	declared := []string{"127.0.0.1:8080/tcp"}
	finalValue := testPeerPortFinalValue(
		sessionDigest,
		adapter,
		namespaces,
		declared,
	)
	finalRaw, err := json.Marshal(finalValue)
	if err != nil {
		t.Fatal(err)
	}
	result, err := decodePeerPortFinalFrame(
		finalRaw,
		sessionDigest,
		adapter,
		namespaces,
		declared,
	)
	if err != nil || result.SampleCount != 3 {
		t.Fatalf("valid FINAL frame rejected: %#v, %v", result, err)
	}

	finalMutations := map[string]func(map[string]any){
		"unknown": func(value map[string]any) {
			value["rawProcNet"] = "forbidden"
		},
		"missing": func(value map[string]any) {
			delete(value, "transitionCount")
		},
		"initial-declared-present": func(value map[string]any) {
			value["initialEndpoints"] = []string{
				"127.0.0.1:8080/tcp",
			}
		},
		"short-cap-eff": func(value map[string]any) {
			value["capEff"] = "00000000"
		},
		"malformed-cap-eff": func(value map[string]any) {
			value["capEff"] = "000000000000000g"
		},
		"gap": func(value map[string]any) {
			value["gapDetected"] = true
		},
		"overflow": func(value map[string]any) {
			value["overflowDetected"] = true
		},
		"sample-bound": func(value map[string]any) {
			value["sampleCount"] = peerPortSampleLimit + 1
		},
		"sample-consistency": func(value map[string]any) {
			value["sampleCount"] = 2
		},
		"transition-consistency": func(value map[string]any) {
			value["transitionCount"] = 1
		},
	}
	for name, mutate := range finalMutations {
		t.Run("final-"+name, func(t *testing.T) {
			copied := clonePeerPortJSONMap(finalValue)
			mutate(copied)
			raw, err := json.Marshal(copied)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodePeerPortFinalFrame(
				raw,
				sessionDigest,
				adapter,
				namespaces,
				declared,
			); err == nil {
				t.Fatal("invalid FINAL frame was accepted")
			}
		})
	}

	duplicateFinal := strings.Replace(
		string(finalRaw),
		`"type":"final"`,
		`"type":"final","type":"final"`,
		1,
	)
	for name, raw := range map[string][]byte{
		"duplicate": []byte(duplicateFinal),
		"trailing": append(
			append([]byte(nil), finalRaw...),
			[]byte(`{}`)...,
		),
	} {
		t.Run("final-"+name, func(t *testing.T) {
			if _, err := decodePeerPortFinalFrame(
				raw,
				sessionDigest,
				adapter,
				namespaces,
				declared,
			); err == nil {
				t.Fatal("invalid FINAL transport was accepted")
			}
		})
	}

	dirtyStdout := newActivityTraceFrameStream()
	_, _ = dirtyStdout.Write(append(append([]byte(nil), ready...), '\n'))
	_, _ = dirtyStdout.Write(append(append([]byte(nil), finalRaw...), '\n'))
	_, _ = dirtyStdout.Write([]byte("dirty"))
	if dirtyStdout.complete() {
		t.Fatal("trailing stdout bytes were accepted")
	}
	dirtyStderr := &activityTraceLockedBuffer{limit: peerPortStderrLimit}
	_, _ = dirtyStderr.Write([]byte("dirty"))
	if dirtyStderr.clean() {
		t.Fatal("dirty stderr was accepted")
	}
}

func TestPeerPortCreateArgsPinSecurityImageAndNetwork(t *testing.T) {
	targetID := strings.Repeat("a", 64)
	for _, testCase := range []struct {
		name       string
		adapter    string
		image      string
		executable string
		adapterID  string
		scriptArgs []string
	}{
		{
			name:       "node",
			adapter:    "node",
			image:      runtimepolicy.NodeReference,
			executable: "node",
			adapterID:  "node-proc-net-tcp-linux",
			scriptArgs: []string{"-e", nodePeerPortObserverScript},
		},
		{
			name:       "python",
			adapter:    "python",
			image:      runtimepolicy.PythonReference,
			executable: "python",
			adapterID:  "python-proc-net-tcp-linux",
			scriptArgs: []string{
				"-I", "-S", "-c", pythonPeerPortObserverScript,
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			plan := domain.ResolvedPlan{
				RuntimeAdapter:     testCase.adapter,
				BaseImageReference: testCase.image,
			}
			prepared := &PreparedRun{
				Plan:          plan,
				Backend:       "docker",
				Platform:      "linux/amd64",
				RunID:         "test1234",
				executionPlan: plan,
			}
			name, args, adapter, err := buildPeerPortCreateArgs(
				prepared,
				targetID,
			)
			if err != nil {
				t.Fatalf("secure peer create argv rejected: %v", err)
			}
			if name != "repopass-port-test1234" ||
				adapter != testCase.adapterID {
				t.Fatalf(
					"unexpected peer identity: %q, %q",
					name,
					adapter,
				)
			}
			expected := []string{
				"create", "--interactive",
				"--name", "repopass-port-test1234",
				"--label", runLabelKey + "=test1234",
				"--label", peerPortObserverLabelKey + "=" +
					peerPortObserverLabelValue,
				"--platform", "linux/amd64",
				"--network", "container:" + targetID,
				"--ipc", "none",
				"--cgroupns", "private",
				"--user", "65534:65534",
				"--cap-drop", "ALL",
				"--security-opt", "no-new-privileges=true",
				"--pids-limit", strconv.Itoa(peerPortPIDsLimit),
				"--memory", strconv.FormatInt(peerPortMemoryBytes, 10),
				"--memory-swap",
				strconv.FormatInt(peerPortMemoryBytes, 10),
				"--cpus", "0.25",
				"--read-only",
				"--workdir", "/",
				"--env", "NODE_OPTIONS=",
				"--env", "NODE_PATH=",
				"--env", "PYTHONPATH=",
				"--env", "PYTHONHOME=",
				"--stop-timeout", "2",
				"--ulimit", "nofile=64:64",
				"--pull=never",
				"--entrypoint", testCase.executable,
				testCase.image,
			}
			expected = append(expected, testCase.scriptArgs...)
			if !slices.Equal(args, expected) {
				t.Fatalf(
					"peer create argv drifted:\nwant: %#v\n got: %#v",
					expected,
					args,
				)
			}
		})
	}
}

func TestPeerPortHelperSourcesUseBoundedTCPOnlyReadsAndStrictUTF8(t *testing.T) {
	for _, required := range []string{
		`Buffer.allocUnsafe(max+1)`,
		`fs.readSync(fd,value,size,value.length-size,null)`,
		`Buffer.from(text,"utf8").equals(line)`,
		`/proc/net/tcp`,
		`/proc/net/tcp6`,
		`fields[3]!=="0A"`,
	} {
		if !strings.Contains(nodePeerPortObserverScript, required) {
			t.Fatalf("Node helper lost required bound %q", required)
		}
	}
	if strings.Contains(nodePeerPortObserverScript, "readFileSync(name)") {
		t.Fatal("Node helper regressed to an unbounded proc table read")
	}
	const namespacePattern = `new RegExp("^"+name+":\\[[0-9]{1,20}\\]$")`
	if !strings.Contains(nodePeerPortObserverScript, namespacePattern) {
		t.Fatal("Node helper lost its exact proc namespace-link pattern")
	}
	const overEscapedNamespacePattern = `new RegExp("^"+name+":\\\\[[0-9]{1,20}\\\\]$")`
	if strings.Contains(nodePeerPortObserverScript, overEscapedNamespacePattern) {
		t.Fatal("Node helper namespace-link pattern is over-escaped")
	}
	for _, required := range []string{
		`source.read(limit+1)`,
		`/proc/net/tcp`,
		`/proc/net/tcp6`,
		`fields[3]!="0A"`,
	} {
		if !strings.Contains(pythonPeerPortObserverScript, required) {
			t.Fatalf("Python helper lost required bound %q", required)
		}
	}
	for _, forbidden := range []string{
		"/proc/net/udp",
		"/proc/net/raw",
		"/proc/net/unix",
	} {
		if strings.Contains(nodePeerPortObserverScript, forbidden) ||
			strings.Contains(pythonPeerPortObserverScript, forbidden) {
			t.Fatalf("peer helper expanded beyond TCP scope: %q", forbidden)
		}
	}
}

func TestPeerPortIdentityTemplateSerializesPointerPIDsLimitAsValue(
	t *testing.T,
) {
	pidsLimit := int64(peerPortPIDsLimit)
	var nilStrings *[]string
	var nilMounts *[]map[string]any
	var nilDevices *[]map[string]any
	var nilPortBindings *map[string]any
	targetID := strings.Repeat("a", 64)
	peerID := strings.Repeat("b", 64)
	data := map[string]any{
		"Id": peerID,
		"Config": map[string]any{
			"Labels": map[string]string{
				"dev.repopass.run":      "test1234",
				"dev.repopass.observer": peerPortObserverLabelValue,
			},
			"Image": runtimepolicy.NodeReference,
			"User":  "65534:65534",
		},
		"HostConfig": map[string]any{
			"NetworkMode":    "container:" + targetID,
			"PidMode":        "",
			"IpcMode":        "none",
			"CgroupnsMode":   "private",
			"ReadonlyRootfs": true,
			"Memory":         json.Number(strconv.FormatInt(peerPortMemoryBytes, 10)),
			"MemorySwap":     json.Number(strconv.FormatInt(peerPortMemoryBytes, 10)),
			"PidsLimit":      &pidsLimit,
			"NanoCpus":       json.Number(strconv.FormatInt(peerPortNanoCPUs, 10)),
			"CapDrop":        []string{"ALL"},
			"SecurityOpt":    []string{"no-new-privileges"},
			"Privileged":     false,
			"CapAdd":         nilStrings,
			"Binds":          nilStrings,
			"Devices":        nilDevices,
			"PortBindings":   nilPortBindings,
		},
		"Mounts": nilMounts,
		"State": map[string]any{
			"Running": false,
		},
	}
	if strings.Contains(peerPortContainerIdentityFormat, "(len ") {
		t.Fatal("peer identity template performs len on a possibly nil pointer")
	}
	identityTemplate, err := template.New("peer-identity").
		Funcs(template.FuncMap{
			"json": func(value any) string {
				encoded, marshalErr := json.Marshal(value)
				if marshalErr != nil {
					t.Fatalf("could not render JSON template value: %v", marshalErr)
				}
				return string(encoded)
			},
		}).
		Parse(peerPortContainerIdentityFormat)
	if err != nil {
		t.Fatalf("peer identity template did not parse: %v", err)
	}
	var rendered strings.Builder
	if err := identityTemplate.Execute(&rendered, data); err != nil {
		t.Fatalf("peer identity template did not execute: %v", err)
	}
	identity, err := decodePeerPortContainerIdentity(
		[]byte(rendered.String()),
	)
	if err != nil {
		t.Fatalf("rendered peer identity was rejected: %v", err)
	}
	if identity.PIDsLimit != peerPortPIDsLimit {
		t.Fatalf(
			"pointer PIDs limit rendered as %d; want %d",
			identity.PIDsLimit,
			peerPortPIDsLimit,
		)
	}
	plan := domain.ResolvedPlan{
		RuntimeAdapter:     "node",
		BaseImageReference: runtimepolicy.NodeReference,
	}
	prepared := &PreparedRun{
		Plan:          plan,
		Backend:       "docker",
		Platform:      "linux/amd64",
		RunID:         "test1234",
		executionPlan: plan,
	}
	stopped := false
	if err := validatePeerPortContainerIdentity(
		identity,
		prepared,
		targetID,
		peerID,
		&stopped,
	); err != nil {
		t.Fatalf("rendered nil-pointer identity was rejected: %v", err)
	}
}

func TestPeerPortIdentityAndNamespaceIsolationAreExact(t *testing.T) {
	targetID := strings.Repeat("a", 64)
	peerID := strings.Repeat("b", 64)
	plan := domain.ResolvedPlan{
		RuntimeAdapter:     "node",
		BaseImageReference: runtimepolicy.NodeReference,
	}
	prepared := &PreparedRun{
		Plan:          plan,
		Backend:       "docker",
		Platform:      "linux/amd64",
		RunID:         "test1234",
		executionPlan: plan,
	}
	targetRaw := []byte(fmt.Sprintf(
		`{"id":%q,"runLabel":"test1234","imageReference":%q,"running":true}`,
		targetID,
		runtimepolicy.NodeReference,
	))
	target, err := decodePeerPortTargetIdentity(targetRaw)
	if err != nil {
		t.Fatalf("valid target identity rejected: %v", err)
	}
	if err := validatePeerPortTargetIdentity(
		target,
		prepared,
		targetID,
		true,
	); err != nil {
		t.Fatalf("valid target identity did not match: %v", err)
	}
	target.RunLabel = "swapped"
	if err := validatePeerPortTargetIdentity(
		target,
		prepared,
		targetID,
		true,
	); err == nil {
		t.Fatal("swapped target identity was accepted")
	}
	if _, err := decodePeerPortTargetIdentity(
		append(targetRaw, []byte(`{}`)...),
	); err == nil {
		t.Fatal("target identity with trailing data was accepted")
	}

	peerRaw := []byte(fmt.Sprintf(
		`{"id":%q,"runLabel":"test1234","observerLabel":%q,`+
			`"imageReference":%q,"networkMode":"container:%s",`+
			`"pidMode":"","ipcMode":"none","cgroupnsMode":"private",`+
			`"user":"65534:65534","readOnlyRootfs":true,`+
			`"memoryBytes":%d,"memorySwap":%d,"pidsLimit":%d,`+
			`"nanoCPUs":%d,"capDrop":["ALL"],`+
			`"securityOpt":["no-new-privileges"],`+
			`"privileged":false,"capAdd":[],"binds":[],`+
			`"mounts":[],"devices":[],"portBindings":{},`+
			`"running":true}`,
		peerID,
		peerPortObserverLabelValue,
		runtimepolicy.NodeReference,
		targetID,
		peerPortMemoryBytes,
		peerPortMemoryBytes,
		peerPortPIDsLimit,
		peerPortNanoCPUs,
	))
	peer, err := decodePeerPortContainerIdentity(peerRaw)
	if err != nil {
		t.Fatalf("valid peer identity rejected: %v", err)
	}
	running := true
	if err := validatePeerPortContainerIdentity(
		peer,
		prepared,
		targetID,
		peerID,
		&running,
	); err != nil {
		t.Fatalf("valid peer security identity rejected: %v", err)
	}
	for name, mutate := range map[string]func(*peerPortContainerIdentity){
		"image": func(identity *peerPortContainerIdentity) {
			identity.ImageReference = "untrusted:latest"
		},
		"network": func(identity *peerPortContainerIdentity) {
			identity.NetworkMode = "bridge"
		},
		"pid-share": func(identity *peerPortContainerIdentity) {
			identity.PIDMode = "container:" + targetID
		},
		"writable-root": func(identity *peerPortContainerIdentity) {
			identity.ReadOnlyRootfs = false
		},
		"privileged": func(identity *peerPortContainerIdentity) {
			identity.Privileged = true
		},
		"cap-add": func(identity *peerPortContainerIdentity) {
			identity.CapAdd = []string{"NET_ADMIN"}
		},
		"mount": func(identity *peerPortContainerIdentity) {
			identity.Mounts = []json.RawMessage{
				json.RawMessage(`{}`),
			}
		},
		"bind": func(identity *peerPortContainerIdentity) {
			identity.Binds = []string{"/host:/guest"}
		},
		"device": func(identity *peerPortContainerIdentity) {
			identity.Devices = []json.RawMessage{
				json.RawMessage(`{}`),
			}
		},
		"port-binding": func(identity *peerPortContainerIdentity) {
			identity.PortBindings = map[string]json.RawMessage{
				"8080/tcp": json.RawMessage(`[]`),
			}
		},
		"running-state": func(identity *peerPortContainerIdentity) {
			identity.Running = false
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := peer
			mutate(&changed)
			if err := validatePeerPortContainerIdentity(
				changed,
				prepared,
				targetID,
				peerID,
				&running,
			); err == nil {
				t.Fatal("mutated peer security identity was accepted")
			}
		})
	}

	targetNamespaces := testPeerPortNamespaces(
		"100",
		"200",
		"300",
		"400",
		"500",
	)
	peerNamespaces := testPeerPortNamespaces(
		"100",
		"201",
		"301",
		"401",
		"501",
	)
	if err := validatePeerPortNamespaceIsolation(
		peerNamespaces,
		targetNamespaces,
	); err != nil {
		t.Fatalf("valid namespace isolation rejected: %v", err)
	}
	netMismatch := peerNamespaces
	netMismatch.Net = "net:[999]"
	if err := validatePeerPortNamespaceIsolation(
		netMismatch,
		targetNamespaces,
	); err == nil {
		t.Fatal("network namespace mismatch was accepted")
	}
	pidShared := peerNamespaces
	pidShared.PID = targetNamespaces.PID
	if err := validatePeerPortNamespaceIsolation(
		pidShared,
		targetNamespaces,
	); err == nil {
		t.Fatal("shared PID namespace was accepted")
	}
}

func TestPeerPortRemovalRequiresExactImmutableIDConfirmation(t *testing.T) {
	peerID := strings.Repeat("b", 64)
	success := &peerPortRemovalExecutor{stdout: peerID + "\n"}
	if err := NewRunner(
		success,
		DefaultConfig(),
	).removePeerPortContainer(context.Background(), peerID); err != nil {
		t.Fatalf("exact peer removal confirmation rejected: %v", err)
	}
	if success.name != "docker" ||
		!slices.Equal(
			success.args,
			[]string{"rm", "--force", peerID},
		) {
		t.Fatalf(
			"unexpected peer removal command: %q %#v",
			success.name,
			success.args,
		)
	}

	for name, executor := range map[string]*peerPortRemovalExecutor{
		"missing-newline": {stdout: peerID},
		"wrong-id":        {stdout: strings.Repeat("c", 64) + "\n"},
		"dirty-stderr":    {stdout: peerID + "\n", stderr: "warning"},
		"nonzero":         {stdout: peerID + "\n", exitCode: 1},
		"transport-error": {
			stdout: peerID + "\n",
			err:    errors.New("transport failed"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := NewRunner(
				executor,
				DefaultConfig(),
			).removePeerPortContainer(context.Background(), peerID)
			if err == nil {
				t.Fatal("unconfirmed peer removal was accepted")
			}
		})
	}
	invalid := &peerPortRemovalExecutor{}
	if err := NewRunner(
		invalid,
		DefaultConfig(),
	).removePeerPortContainer(
		context.Background(),
		"repopass-port-test1234",
	); err == nil {
		t.Fatal("mutable peer name was accepted for removal")
	}
	if invalid.calls != 0 {
		t.Fatal("invalid removal identity reached the executor")
	}
}

func TestPeerPortSummaryDetectsAggregateUndeclaredListenersAndRedactsEndpoints(
	t *testing.T,
) {
	declared := []string{"127.0.0.1:8080/tcp"}
	undeclared := []string{
		"10.9.8.7:65000/tcp",
		"10.9.8.8:65001/tcp",
	}
	digest := "sha256:" + strings.Repeat("c", 64)
	secretID := strings.Repeat("d", 64)
	completedAt := time.Date(
		2026,
		time.July,
		31,
		1,
		2,
		3,
		0,
		time.UTC,
	)
	successState := peerPortObservationState{
		required:                   true,
		backendEligible:            true,
		targetID:                   secretID,
		peerID:                     secretID,
		declaredEndpoints:          cloneStrings(declared),
		startIdentityVerified:      true,
		readyIdentityVerified:      true,
		finalIdentityVerified:      true,
		namespaceIsolationVerified: true,
		workloadQuiescenceVerified: true,
		peerRemoveVerified:         true,
		ready:                      true,
		finalReady:                 true,
		result: peerPortResult{
			Adapter:                   "node-proc-net-tcp-linux",
			SampleCount:               3,
			MaxSampleGapMillis:        105,
			TransitionCount:           6,
			ObservedEndpoints:         cloneStrings(declared),
			InitialEndpoints:          []string{},
			FinalEndpoints:            []string{},
			DeclaredEndpoints:         cloneStrings(declared),
			DeclaredObservedEndpoints: cloneStrings(declared),
			DeclaredClosedEndpoints:   cloneStrings(declared),
			CanonicalSampleDigest:     digest,
		},
		observedAt: completedAt.Add(-time.Second),
	}
	event, coverage, finding := summarizePeerPortObservation(
		successState,
		completedAt,
	)
	if coverage != coverageBestEffort ||
		event.Coverage != coverageBestEffort ||
		event.Result != "observed" ||
		event.Confidence != "high" ||
		event.Operation != "port.listener-trace.summary" {
		t.Fatalf("unexpected successful port summary: %#v", event)
	}
	if finding != nil ||
		event.Details["comparisonResult"] !=
			peerPortComparisonNegative ||
		event.Details["declaredEndpointCount"] != 1 ||
		event.Details["baselineEndpointCount"] != 0 ||
		event.Details["sampledEndpointCount"] != 1 ||
		event.Details["undeclaredEndpointCount"] != 0 ||
		event.Details["canonicalSampleDigest"] != digest {
		t.Fatalf("successful aggregate evidence is incomplete: %#v", event.Details)
	}
	if len(event.Details) != 30 {
		t.Fatalf(
			"successful public detail surface = %d keys, want 30",
			len(event.Details),
		)
	}

	positiveState := successState
	positiveState.result.ObservedEndpoints = []string{
		undeclared[0], undeclared[1], declared[0],
	}
	positiveEvent, positiveCoverage, positiveFinding :=
		summarizePeerPortObservation(positiveState, completedAt)
	if positiveCoverage != coverageBestEffort ||
		positiveEvent.Details["comparisonResult"] !=
			peerPortComparisonPositive ||
		positiveEvent.Details["undeclaredEndpointCount"] != 2 ||
		positiveFinding == nil ||
		positiveFinding.Code != domain.CodeUndeclaredPortListen ||
		positiveFinding.Severity != domain.SeverityHigh ||
		len(positiveFinding.Details) != 3 ||
		positiveFinding.Details["observer"] !=
			"docker-peer-port-listener-trace" ||
		positiveFinding.Details["evidenceBasis"] != "aggregate-only" ||
		positiveFinding.Details["undeclaredEndpointCount"] != 2 {
		t.Fatalf(
			"positive aggregate comparison event=%#v finding=%#v",
			positiveEvent,
			positiveFinding,
		)
	}
	if len(positiveFinding.EvidenceRefs) != 0 ||
		positiveFinding.Retryable {
		t.Fatalf("positive finding envelope = %#v", positiveFinding)
	}

	successJSON, err := json.Marshal([]any{
		event,
		positiveEvent,
		positiveFinding,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append([]string{
		secretID,
		"/proc/net/tcp",
		"inode",
		"declaredEndpoints",
		"declaredObservedEndpoints",
		"declaredClosedEndpoints",
	}, undeclared...) {
		if strings.Contains(string(successJSON), forbidden) {
			t.Fatalf("successful public summary leaked %q", forbidden)
		}
	}

	unavailableState := successState
	unavailableState.failure = "ready-frame-invalid"
	event, coverage, finding = summarizePeerPortObservation(
		unavailableState,
		completedAt,
	)
	if coverage != coverageUnavailable ||
		event.Coverage != coverageUnavailable ||
		event.Result != "unavailable" ||
		event.Confidence != "unknown" || finding != nil ||
		event.Details["comparisonResult"] !=
			peerPortComparisonUntested {
		t.Fatalf("unexpected unavailable port summary: %#v", event)
	}
	for _, key := range []string{
		"observerAdapter",
		"declaredEndpointCount",
		"baselineEndpointCount",
		"sampledEndpointCount",
		"undeclaredEndpointCount",
		"sampleCount",
		"maxSampleGapMillis",
		"transitionCount",
		"canonicalSampleDigest",
	} {
		if _, present := event.Details[key]; present {
			t.Fatalf("unavailable summary exposed %q", key)
		}
	}
	if len(event.Details) != 22 {
		t.Fatalf(
			"unavailable public detail surface = %d keys, want 22",
			len(event.Details),
		)
	}
	unavailableJSON, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range append([]string{
		"node-proc-net-tcp-linux",
		digest,
		secretID,
		"token",
		"/proc/net/tcp",
		"inode",
	}, undeclared...) {
		if strings.Contains(string(unavailableJSON), forbidden) {
			t.Fatalf("unavailable public summary leaked %q", forbidden)
		}
	}

	baselineState := successState
	baselineState.result.InitialEndpoints = []string{undeclared[0]}
	baselineState.result.ObservedEndpoints = []string{
		undeclared[0], declared[0],
	}
	baselineEvent, baselineCoverage, baselineFinding :=
		summarizePeerPortObservation(baselineState, completedAt)
	if baselineCoverage != coverageUnavailable || baselineFinding != nil ||
		baselineEvent.Details["comparisonResult"] !=
			peerPortComparisonUntested {
		t.Fatalf(
			"nonempty baseline was not fail-closed: event=%#v finding=%#v",
			baselineEvent,
			baselineFinding,
		)
	}
	for _, key := range []string{
		"declaredEndpointCount",
		"baselineEndpointCount",
		"sampledEndpointCount",
		"undeclaredEndpointCount",
	} {
		if _, present := baselineEvent.Details[key]; present {
			t.Fatalf("nonempty baseline published %q", key)
		}
	}
}

func TestPeerPortLifecycleStartsBeforeServiceFinalizesAfterQuiescenceAndRemovesFirst(
	t *testing.T,
) {
	sourceRoot := t.TempDir()
	mustWriteFile(
		t,
		sourceRoot+"/server.js",
		[]byte("server fixture\n"),
	)
	plan := testHTTPPlan(t, sourceRoot)
	plan.ObserverSet = []string{"port-listen"}
	plan.ObserverVersions = map[string]string{
		"port-listen": "0.2.0",
	}
	plan.RequiredRunnerFeatures = append(
		plan.RequiredRunnerFeatures,
		"observer:port-listen",
	)

	serviceStopped := make(chan struct{})
	var stopOnce sync.Once
	var lifecycle *peerPortLifecycleExecutor
	base := successfulNodeSandbox(func(
		ctx context.Context,
		_ string,
		args []string,
		_ io.Writer,
		_ io.Writer,
	) (int, error) {
		if !containsArgument(args, "/workspace/server.js") {
			return 0, nil
		}
		if lifecycle == nil || !lifecycle.readyBeforeService() {
			return -1, errors.New(
				"service dispatched before peer observer READY",
			)
		}
		select {
		case <-serviceStopped:
			return 143, errors.New("service terminated by signal")
		case <-ctx.Done():
			return -1, ctx.Err()
		}
	})
	input := &inputFakeExecutor{fakeExecutor: &fakeExecutor{}}
	lifecycle = newPeerPortLifecycleExecutor(input, serviceStopped)
	lifecycle.undeclaredEndpoints = []string{"10.9.8.7:65000/tcp"}
	input.handler = func(
		ctx context.Context,
		name string,
		args []string,
		stdout io.Writer,
		stderr io.Writer,
	) (int, error) {
		switch {
		case len(args) > 0 && args[0] == "create" &&
			containsArgument(
				args,
				peerPortObserverLabelKey+"="+
					peerPortObserverLabelValue,
			):
			_, _ = io.WriteString(stdout, lifecycle.peerID+"\n")
			return 0, nil
		case containsArgument(args, peerPortTargetIdentityFormat):
			_, _ = fmt.Fprintf(
				stdout,
				`{"id":%q,"runLabel":"test1234",`+
					`"imageReference":%q,"running":true}`+"\n",
				lifecycle.targetID,
				runtimepolicy.NodeReference,
			)
			return 0, nil
		case containsArgument(args, peerPortContainerIdentityFormat):
			_, _ = io.WriteString(
				stdout,
				lifecycle.peerIdentityJSON()+"\n",
			)
			return 0, nil
		case containsArgument(args, nodeTargetNamespaceScript):
			_, _ = io.WriteString(
				stdout,
				`{"net":"net:[100]","pid":"pid:[200]",`+
					`"mnt":"mnt:[300]","ipc":"ipc:[400]",`+
					`"cgroup":"cgroup:[500]"}`+"\n",
			)
			return 0, nil
		case len(args) == 3 &&
			slices.Equal(
				args,
				[]string{"rm", "--force", lifecycle.peerID},
			):
			if !lifecycle.finalBeforeRemove() {
				return -1, errors.New(
					"peer removed before FINAL completed",
				)
			}
			_, _ = io.WriteString(stdout, lifecycle.peerID+"\n")
			return 0, nil
		case containsArgument(args, nodeServiceSignalScript):
			stopOnce.Do(func() { close(serviceStopped) })
			_, _ = io.WriteString(
				stdout,
				`{"ok":true,"escalated":false,"remaining":0,`+
					`"initialTargets":1,"sent":1}`+"\n",
			)
			return 0, nil
		default:
			return base(ctx, name, args, stdout, stderr)
		}
	}
	input.inputHandler = func(
		_ context.Context,
		_ string,
		args []string,
		_ []byte,
		stdout io.Writer,
		_ io.Writer,
	) (int, error) {
		if !containsArgument(args, nodeHTTPHelperScript) {
			return -1, errors.New("unexpected input command")
		}
		body := []byte("hello from peer lifecycle")
		_, _ = fmt.Fprintf(
			stdout,
			`{"ok":true,"status":200,`+
				`"headers":[{"name":"content-type",`+
				`"value":"text/plain"}],`+
				`"bodyBase64":%q,"bodyBytes":%d,`+
				`"bodyTruncated":false,"durationMillis":1}`+"\n",
			base64.StdEncoding.EncodeToString(body),
			len(body),
		)
		return 0, nil
	}

	outcome, err := testRunner(lifecycle).Execute(
		context.Background(),
		plan,
		sourceRoot,
		t.TempDir(),
		"docker",
	)
	if err != nil {
		t.Fatalf(
			"peer port lifecycle execution failed: %v; outcome=%#v",
			err,
			outcome,
		)
	}
	if outcome.Runner.PortObservation != coverageBestEffort {
		t.Fatalf(
			"port coverage = %q, want best-effort",
			outcome.Runner.PortObservation,
		)
	}
	if !containsString(
		outcome.IncompleteFeatures,
		"observer:port-listen",
	) {
		t.Fatalf(
			"required best-effort observer was incorrectly completed: %#v",
			outcome.IncompleteFeatures,
		)
	}
	if len(outcome.Errors) != 1 ||
		outcome.Errors[0].Code != domain.CodeUndeclaredPortListen ||
		outcome.Errors[0].Details["undeclaredEndpointCount"] != 1 {
		t.Fatalf(
			"positive peer listener did not produce one aggregate finding: %#v",
			outcome.Errors,
		)
	}
	publicOutcome, marshalErr := json.Marshal(outcome)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if bytes.Contains(publicOutcome, []byte(lifecycle.undeclaredEndpoints[0])) {
		t.Fatal("positive peer listener endpoint leaked into the public outcome")
	}
	if bytes.Contains(publicOutcome, []byte("hello")) {
		t.Fatal("repository-controlled HTTP substring leaked into the public outcome")
	}
	assertionJSON, err := json.Marshal(map[string]any{
		"assertions": outcome.Assertions,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := privacy.Evaluate(assertionJSON); err != nil {
		if blocked, ok := err.(*domain.Error); ok {
			t.Fatalf(
				"positive peer listener public assertions failed privacy gate: rules=%v surfaces=%v findings=%v",
				blocked.Details["ruleIds"],
				blocked.Details["surfaces"],
				blocked.Details["findingCount"],
			)
		}
		t.Fatalf("positive peer listener public assertions failed privacy gate: %v", err)
	}
	if !lifecycle.finalAfterServiceQuiescence() {
		t.Fatal("peer FINAL was not ordered after service quiescence")
	}

	calls := input.snapshotCalls()
	peerStart := -1
	serviceStart := -1
	peerRemove := -1
	targetRemove := -1
	for index, call := range calls {
		switch {
		case slices.Equal(
			call.args,
			[]string{
				"start", "--attach", "--interactive",
				lifecycle.peerID,
			},
		):
			peerStart = index
		case containsArgument(call.args, "/workspace/server.js"):
			serviceStart = index
		case slices.Equal(
			call.args,
			[]string{"rm", "--force", lifecycle.peerID},
		):
			peerRemove = index
		case slices.Equal(
			call.args,
			[]string{"rm", "-f", strings.Repeat("a", 64)},
		):
			targetRemove = index
		}
	}
	if peerStart < 0 || serviceStart <= peerStart {
		t.Fatalf(
			"peer READY/start did not precede service: peer=%d service=%d",
			peerStart,
			serviceStart,
		)
	}
	if peerRemove < 0 || targetRemove <= peerRemove {
		t.Fatalf(
			"peer removal did not precede target: peer=%d target=%d",
			peerRemove,
			targetRemove,
		)
	}
}

func testPeerPortPlan() domain.ResolvedPlan {
	return domain.ResolvedPlan{
		RuntimeAdapter: "node",
		JourneyDriver:  "http",
		HTTPJourney: &domain.PlanHTTPJourney{
			ServiceID: "server",
		},
		Commands: []domain.PlanCommand{
			{
				Phase: domain.PhaseRun,
				ID:    "server",
				Role:  "service",
				Readiness: &domain.PlanHTTPReadiness{
					URL:     "http://127.0.0.1:8080/ready",
					Status:  200,
					Timeout: "5s",
				},
			},
			{
				Phase: domain.PhaseCleanup,
				ID:    "stop-server",
				Role:  "signal",
			},
		},
		Capabilities: map[domain.Phase]domain.CapabilitySet{
			domain.PhaseRun: {
				Ports: domain.PortCapability{
					Listen: []domain.PortBinding{
						{
							Host:     "127.0.0.1",
							Port:     8080,
							Protocol: "tcp",
						},
					},
				},
			},
		},
	}
}

func testPeerPortNamespaces(
	netID string,
	pidID string,
	mountID string,
	ipcID string,
	cgroupID string,
) peerPortNamespaces {
	return peerPortNamespaces{
		Net:    "net:[" + netID + "]",
		PID:    "pid:[" + pidID + "]",
		Mount:  "mnt:[" + mountID + "]",
		IPC:    "ipc:[" + ipcID + "]",
		Cgroup: "cgroup:[" + cgroupID + "]",
	}
}

func testPeerPortNamespaceValue(
	namespaces peerPortNamespaces,
) map[string]any {
	return map[string]any{
		"net":    namespaces.Net,
		"pid":    namespaces.PID,
		"mnt":    namespaces.Mount,
		"ipc":    namespaces.IPC,
		"cgroup": namespaces.Cgroup,
	}
}

func testPeerPortReadyJSON(
	t *testing.T,
	sessionDigest string,
	adapter string,
	namespaces peerPortNamespaces,
) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"type":                  "ready",
		"schemaVersion":         "1",
		"sessionDigest":         sessionDigest,
		"observerAdapter":       adapter,
		"initialSampleComplete": true,
		"namespaces":            testPeerPortNamespaceValue(namespaces),
		"capEff":                "0000000000000000",
		"noNewPrivs":            true,
		"uid":                   65534,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testPeerPortFinalValue(
	sessionDigest string,
	adapter string,
	namespaces peerPortNamespaces,
	declared []string,
) map[string]any {
	return map[string]any{
		"type":                      "final",
		"schemaVersion":             "1",
		"sessionDigest":             sessionDigest,
		"ok":                        true,
		"observerAdapter":           adapter,
		"namespaces":                testPeerPortNamespaceValue(namespaces),
		"capEff":                    "0000000000000000",
		"noNewPrivs":                true,
		"uid":                       65534,
		"sampleCount":               3,
		"intervalMillis":            peerPortIntervalMillis,
		"maxSampleGapMillis":        105,
		"transitionCount":           2,
		"observedEndpoints":         cloneStrings(declared),
		"initialEndpoints":          []string{},
		"finalEndpoints":            []string{},
		"declaredEndpoints":         cloneStrings(declared),
		"declaredObservedEndpoints": cloneStrings(declared),
		"declaredClosedEndpoints":   cloneStrings(declared),
		"canonicalSampleDigest": "sha256:" +
			strings.Repeat("c", 64),
		"canonicalByteCount": 256,
		"overflowDetected":   false,
		"gapDetected":        false,
	}
}

func clonePeerPortJSONMap(value map[string]any) map[string]any {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		panic(err)
	}
	return result
}

type peerPortRemovalExecutor struct {
	stdout   string
	stderr   string
	exitCode int
	err      error
	name     string
	args     []string
	calls    int
}

type peerPortLifecycleExecutor struct {
	*inputFakeExecutor
	targetID string
	peerID   string

	lifecycleMu         sync.Mutex
	peerRunning         bool
	readyEmitted        bool
	finalEmitted        bool
	finalAfterStop      bool
	serviceStopped      <-chan struct{}
	undeclaredEndpoints []string
}

func newPeerPortLifecycleExecutor(
	input *inputFakeExecutor,
	serviceStopped <-chan struct{},
) *peerPortLifecycleExecutor {
	return &peerPortLifecycleExecutor{
		inputFakeExecutor: input,
		targetID:          strings.Repeat("a", 64),
		peerID:            strings.Repeat("b", 64),
		serviceStopped:    serviceStopped,
	}
}

func (e *peerPortLifecycleExecutor) Start(
	ctx context.Context,
	name string,
	args []string,
	stdout io.Writer,
	_ io.Writer,
) (RunningCommand, error) {
	if name != "docker" || !slices.Equal(
		args,
		[]string{
			"start", "--attach", "--interactive", e.peerID,
		},
	) {
		return nil, errors.New("unexpected asynchronous command")
	}
	e.fakeExecutor.mu.Lock()
	e.fakeExecutor.calls = append(
		e.fakeExecutor.calls,
		commandCall{name: name, args: cloneStrings(args)},
	)
	e.fakeExecutor.mu.Unlock()

	reader, writer := io.Pipe()
	wait := make(chan activityTraceProcessResult, 1)
	process := &scriptedActivityTraceProcess{
		stdin: writer,
		wait:  wait,
	}
	go func() {
		finish := func(exitCode int, err error) {
			_ = reader.Close()
			wait <- activityTraceProcessResult{
				exitCode: exitCode,
				err:      err,
			}
		}
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(
			make([]byte, 0, 512),
			peerPortControlLimit,
		)
		if !scanner.Scan() {
			finish(-1, errors.New("missing peer start frame"))
			return
		}
		var start struct {
			Command           string   `json:"command"`
			Token             string   `json:"token"`
			IntervalMillis    int      `json:"intervalMillis"`
			MaxSamples        int      `json:"maxSamples"`
			MaxGapMillis      int      `json:"maxGapMillis"`
			DeclaredEndpoints []string `json:"declaredEndpoints"`
		}
		if json.Unmarshal(scanner.Bytes(), &start) != nil ||
			start.Command != "start" ||
			len(start.Token) != 64 ||
			start.IntervalMillis != peerPortIntervalMillis ||
			start.MaxSamples != peerPortSampleLimit ||
			start.MaxGapMillis != peerPortMaxGapMillis ||
			!slices.Equal(
				start.DeclaredEndpoints,
				[]string{"127.0.0.1:8080/tcp"},
			) {
			finish(-1, errors.New("invalid peer start frame"))
			return
		}
		sessionDigest := peerPortSessionDigest(start.Token)
		e.lifecycleMu.Lock()
		e.peerRunning = true
		e.readyEmitted = true
		e.lifecycleMu.Unlock()
		ready := map[string]any{
			"type":                  "ready",
			"schemaVersion":         "1",
			"sessionDigest":         sessionDigest,
			"observerAdapter":       "node-proc-net-tcp-linux",
			"initialSampleComplete": true,
			"namespaces": map[string]string{
				"net":    "net:[100]",
				"pid":    "pid:[201]",
				"mnt":    "mnt:[301]",
				"ipc":    "ipc:[401]",
				"cgroup": "cgroup:[501]",
			},
			"capEff":     "0000000000000000",
			"noNewPrivs": true,
			"uid":        65534,
		}
		readyRaw, _ := json.Marshal(ready)
		_, _ = stdout.Write(append(readyRaw, '\n'))
		if !scanner.Scan() {
			select {
			case <-ctx.Done():
				finish(-1, ctx.Err())
			default:
				finish(-1, errors.New("missing peer stop frame"))
			}
			return
		}
		var stop map[string]string
		if json.Unmarshal(scanner.Bytes(), &stop) != nil ||
			stop["command"] != "stop" ||
			stop["token"] != start.Token {
			finish(-1, errors.New("invalid peer stop frame"))
			return
		}
		afterStop := false
		select {
		case <-e.serviceStopped:
			afterStop = true
		default:
		}
		final := testPeerPortFinalValue(
			sessionDigest,
			"node-proc-net-tcp-linux",
			testPeerPortNamespaces(
				"100",
				"201",
				"301",
				"401",
				"501",
			),
			start.DeclaredEndpoints,
		)
		if len(e.undeclaredEndpoints) > 0 {
			observed := append(
				cloneStrings(e.undeclaredEndpoints),
				start.DeclaredEndpoints...,
			)
			sort.Strings(observed)
			final["observedEndpoints"] = observed
			final["transitionCount"] = 2 * len(observed)
		}
		finalRaw, _ := json.Marshal(final)
		_, _ = stdout.Write(append(finalRaw, '\n'))
		e.lifecycleMu.Lock()
		e.peerRunning = false
		e.finalEmitted = true
		e.finalAfterStop = afterStop
		e.lifecycleMu.Unlock()
		finish(0, nil)
	}()
	return process, nil
}

func (e *peerPortLifecycleExecutor) readyBeforeService() bool {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.readyEmitted && e.peerRunning
}

func (e *peerPortLifecycleExecutor) finalBeforeRemove() bool {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.finalEmitted && !e.peerRunning
}

func (e *peerPortLifecycleExecutor) finalAfterServiceQuiescence() bool {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.finalEmitted && e.finalAfterStop
}

func (e *peerPortLifecycleExecutor) peerIdentityJSON() string {
	e.lifecycleMu.Lock()
	running := e.peerRunning
	e.lifecycleMu.Unlock()
	return fmt.Sprintf(
		`{"id":%q,"runLabel":"test1234","observerLabel":%q,`+
			`"imageReference":%q,"networkMode":"container:%s",`+
			`"pidMode":"","ipcMode":"none","cgroupnsMode":"private",`+
			`"user":"65534:65534","readOnlyRootfs":true,`+
			`"memoryBytes":%d,"memorySwap":%d,"pidsLimit":%d,`+
			`"nanoCPUs":%d,"capDrop":["ALL"],`+
			`"securityOpt":["no-new-privileges"],`+
			`"privileged":false,"capAdd":[],"binds":[],`+
			`"mounts":[],"devices":[],"portBindings":{},`+
			`"running":%t}`,
		e.peerID,
		peerPortObserverLabelValue,
		runtimepolicy.NodeReference,
		e.targetID,
		peerPortMemoryBytes,
		peerPortMemoryBytes,
		peerPortPIDsLimit,
		peerPortNanoCPUs,
		running,
	)
}

func (e *peerPortRemovalExecutor) Run(
	_ context.Context,
	name string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) (int, error) {
	e.calls++
	e.name = name
	e.args = cloneStrings(args)
	_, _ = io.WriteString(stdout, e.stdout)
	_, _ = io.WriteString(stderr, e.stderr)
	return e.exitCode, e.err
}
