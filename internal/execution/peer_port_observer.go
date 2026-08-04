package execution

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/repopass/repopass/internal/domain"
)

const (
	peerPortFrameLimit         = 8 << 10
	peerPortTransportLimit     = 16 << 10
	peerPortStderrLimit        = 8 << 10
	peerPortControlLimit       = 2 << 10
	peerPortEndpointLimit      = 16
	peerPortSampleLimit        = 1200
	peerPortTransitionLimit    = 4096
	peerPortCanonicalLimit     = 1 << 20
	peerPortIntervalMillis     = 100
	peerPortMaxGapMillis       = 1000
	peerPortMemoryBytes        = 64 << 20
	peerPortPIDsLimit          = 16
	peerPortNanoCPUs           = 250_000_000
	peerPortControlTimeout     = 2 * time.Second
	peerPortWriteJoinTimeout   = 100 * time.Millisecond
	peerPortObserverLabelKey   = "dev.repopass.observer"
	peerPortObserverLabelValue = "peer-port-listener-trace"
	peerPortNamePrefix         = "repopass-port-"
	peerPortComparisonPositive = "nonconforming-listeners"
	peerPortComparisonNegative = "no-undeclared-observed"
	peerPortComparisonUntested = "not-tested"
)

var (
	peerPortDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	peerPortCapEffPattern = regexp.MustCompile(`^0{16}$`)
	peerNamespacePattern  = regexp.MustCompile(
		`^(net|pid|mnt|ipc|cgroup):\[[0-9]{1,20}\]$`,
	)
)

const (
	peerPortTargetIdentityFormat    = `{{printf "{\"id\":%q,\"runLabel\":%q,\"imageReference\":%q,\"running\":%t}" .Id (index .Config.Labels "dev.repopass.run") .Config.Image .State.Running}}`
	peerPortContainerIdentityFormat = `{{printf "{\"id\":%q,\"runLabel\":%q,\"observerLabel\":%q,\"imageReference\":%q,\"networkMode\":%q,\"pidMode\":%q,\"ipcMode\":%q,\"cgroupnsMode\":%q,\"user\":%q,\"readOnlyRootfs\":%t,\"memoryBytes\":%s,\"memorySwap\":%s,\"pidsLimit\":%s,\"nanoCPUs\":%s,\"capDrop\":%s,\"securityOpt\":%s,\"privileged\":%t,\"capAdd\":%s,\"binds\":%s,\"mounts\":%s,\"devices\":%s,\"portBindings\":%s,\"running\":%t}" .Id (index .Config.Labels "dev.repopass.run") (index .Config.Labels "dev.repopass.observer") .Config.Image .HostConfig.NetworkMode .HostConfig.PidMode .HostConfig.IpcMode .HostConfig.CgroupnsMode .Config.User .HostConfig.ReadonlyRootfs (json .HostConfig.Memory) (json .HostConfig.MemorySwap) (json .HostConfig.PidsLimit) (json .HostConfig.NanoCpus) (json .HostConfig.CapDrop) (json .HostConfig.SecurityOpt) .HostConfig.Privileged (json .HostConfig.CapAdd) (json .HostConfig.Binds) (json .Mounts) (json .HostConfig.Devices) (json .HostConfig.PortBindings) .State.Running}}`
)

const nodePeerPortObserverScript = `const fs=require("node:fs"),crypto=require("node:crypto");
const MAX_INPUT=2048,MAX_FILE=65536,MAX_LINES=4096,MAX_ENDPOINTS=16,MAX_TRANSITIONS=4096,MAX_CANONICAL=1048576,NS=["net","pid","mnt","ipc","cgroup"];
let input=Buffer.alloc(0),started=false,finished=false,timer=null,token="",sessionDigest="",adapter="node-proc-net-tcp-linux",interval=100,maxSamples=1200,maxGap=1000,lastNs=0n,samples=0,transitions=0,maxObservedGap=0,canonicalBytes=0,previous=new Set(),observed=new Set(),initial=[],finalEndpoints=[],declared=[],declaredSet=new Set(),declaredObserved=new Set(),overflow=false,gap=false,mac=null;
function emit(value){process.stdout.write(JSON.stringify(value)+"\n");}
function exact(value,keys){return value&&typeof value==="object"&&!Array.isArray(value)&&Object.keys(value).length===keys.length&&keys.every(key=>Object.prototype.hasOwnProperty.call(value,key));}
function read(name,max){const fd=fs.openSync(name,"r"),value=Buffer.allocUnsafe(max+1);let size=0;try{while(size<value.length){const count=fs.readSync(fd,value,size,value.length-size,null);if(!count)break;size+=count;}}finally{fs.closeSync(fd);}if(size>max)throw new Error("bound");return value.subarray(0,size).toString("ascii");}
function namespaces(){const value={};for(const name of NS){const link=fs.readlinkSync("/proc/self/ns/"+name);if(!new RegExp("^"+name+":\\[[0-9]{1,20}\\]$").test(link))throw new Error("namespace");value[name]=link;}return value;}
function status(){const raw=read("/proc/self/status",16384),lines=raw.split("\n"),one=name=>{const matches=lines.filter(line=>line.startsWith(name+":"));if(matches.length!==1)throw new Error("status");return matches[0].slice(name.length+1).trim();},capEff=one("CapEff"),noNewPrivs=one("NoNewPrivs"),uid=one("Uid").split(/\s+/);if(!/^[0]{16}$/.test(capEff)||noNewPrivs!=="1"||uid.length!==4||uid.some(value=>value!=="65534"))throw new Error("security");return {capEff,noNewPrivs:true,uid:65534};}
function ipv4(raw){if(!/^[A-F0-9]{8}$/.test(raw))throw new Error("ipv4");const parts=[];for(let index=0;index<8;index+=2)parts.push(parseInt(raw.slice(index,index+2),16));return parts.reverse().join(".");}
function ipv6(raw){if(!/^[A-F0-9]{32}$/.test(raw))throw new Error("ipv6");const bytes=[];for(let word=0;word<32;word+=8){const part=[];for(let index=word;index<word+8;index+=2)part.push(parseInt(raw.slice(index,index+2),16));bytes.push(...part.reverse());}const groups=[];for(let index=0;index<16;index+=2)groups.push(((bytes[index]<<8)|bytes[index+1]).toString(16));let best=-1,bestLength=0;for(let index=0;index<groups.length;){if(groups[index]!=="0"){index++;continue;}let end=index;while(end<groups.length&&groups[end]==="0")end++;if(end-index>bestLength&&end-index>=2){best=index;bestLength=end-index;}index=end;}if(best<0)return groups.join(":");const left=groups.slice(0,best).join(":"),right=groups.slice(best+bestLength).join(":");return left+"::"+right;}
function table(name,v6){const raw=read(name,MAX_FILE),lines=raw.trimEnd().split("\n");if(lines.length<1||lines.length>MAX_LINES||!lines[0].includes("local_address"))throw new Error("table");const result=[];for(let index=1;index<lines.length;index++){const fields=lines[index].trim().split(/\s+/);if(fields.length<4||!/^[A-F0-9]{2}$/.test(fields[3]))throw new Error("row");if(fields[3]!=="0A")continue;const local=fields[1].split(":");if(local.length!==2||!/^[A-F0-9]{4}$/.test(local[1]))throw new Error("local");const port=parseInt(local[1],16);if(port<1||port>65535)throw new Error("port");const host=v6?ipv6(local[0]):ipv4(local[0]);result.push((v6?"["+host+"]":host)+":"+port+"/tcp");}return result;}
function snapshot(){const values=[...table("/proc/net/tcp",false),...table("/proc/net/tcp6",true)],unique=[...new Set(values)].sort();if(unique.length>MAX_ENDPOINTS)throw new Error("endpoints");return unique;}
function capture(boundary){if(finished)return false;const now=process.hrtime.bigint();if(lastNs!==0n){const observedGap=Math.ceil(Number(now-lastNs)/1000000);maxObservedGap=Math.max(maxObservedGap,observedGap);if(observedGap>maxGap){gap=true;finish(false);return false;}}lastNs=now;samples++;if(samples>maxSamples){overflow=true;finish(false);return false;}let values;try{values=snapshot();}catch(_){gap=true;finish(false);return false;}const current=new Set(values);if(samples>1){for(const value of current)if(!previous.has(value))transitions++;for(const value of previous)if(!current.has(value))transitions++;if(transitions>MAX_TRANSITIONS){overflow=true;finish(false);return false;}}for(const value of current){observed.add(value);if(declaredSet.has(value))declaredObserved.add(value);}if(observed.size>MAX_ENDPOINTS){overflow=true;finish(false);return false;}if(boundary==="initial")initial=values;if(boundary==="final")finalEndpoints=values;const line=Buffer.from(JSON.stringify([samples,values])+"\n");if(canonicalBytes+line.length>MAX_CANONICAL){overflow=true;finish(false);return false;}mac.update(line);canonicalBytes+=line.length;previous=current;return true;}
function finish(ok){if(finished)return;if(timer!==null){clearInterval(timer);timer=null;}if(ok&&!capture("final"))return;finished=true;let ns={},security={capEff:"",noNewPrivs:false,uid:0};try{ns=namespaces();security=status();}catch(_){gap=true;}const closed=declared.filter(value=>declaredObserved.has(value)&&!new Set(finalEndpoints).has(value));emit({type:"final",schemaVersion:"1",sessionDigest,ok:Boolean(ok&&!overflow&&!gap),observerAdapter:adapter,namespaces:ns,capEff:security.capEff,noNewPrivs:security.noNewPrivs,uid:security.uid,sampleCount:Math.min(samples,maxSamples),intervalMillis:interval,maxSampleGapMillis:maxObservedGap,transitionCount:Math.min(transitions,MAX_TRANSITIONS),observedEndpoints:[...observed].sort(),initialEndpoints:initial,finalEndpoints,declaredEndpoints:declared,declaredObservedEndpoints:declared.filter(value=>declaredObserved.has(value)),declaredClosedEndpoints:closed,canonicalSampleDigest:"sha256:"+mac.digest("hex"),canonicalByteCount:canonicalBytes,overflowDetected:overflow,gapDetected:gap});process.exitCode=ok&&!overflow&&!gap?0:1;process.stdin.pause();}
function begin(value){if(started||!exact(value,["command","token","intervalMillis","maxSamples","maxGapMillis","declaredEndpoints"])||value.command!=="start"||typeof value.token!=="string"||!/^[a-f0-9]{64}$/.test(value.token)||value.intervalMillis!==100||value.maxSamples!==1200||value.maxGapMillis!==1000||!Array.isArray(value.declaredEndpoints)||value.declaredEndpoints.length>MAX_ENDPOINTS||value.declaredEndpoints.some((item,index)=>typeof item!=="string"||item.length>64||(index>0&&value.declaredEndpoints[index-1]>=item))){process.exitCode=1;process.stdin.pause();return;}started=true;token=value.token;sessionDigest="sha256:"+crypto.createHash("sha256").update(token,"ascii").digest("hex");interval=value.intervalMillis;maxSamples=value.maxSamples;maxGap=value.maxGapMillis;declared=value.declaredEndpoints;declaredSet=new Set(declared);mac=crypto.createHmac("sha256",token);let ns,security;try{ns=namespaces();security=status();}catch(_){process.exitCode=1;process.stdin.pause();return;}if(!capture("initial"))return;emit({type:"ready",schemaVersion:"1",sessionDigest,observerAdapter:adapter,initialSampleComplete:true,namespaces:ns,capEff:security.capEff,noNewPrivs:security.noNewPrivs,uid:security.uid});timer=setInterval(()=>capture("poll"),interval);}
function command(value){if(!started){begin(value);return;}if(!exact(value,["command","token"])||value.command!=="stop"||value.token!==token){gap=true;finish(false);return;}finish(true);}
function consume(){for(;;){const newline=input.indexOf(10);if(newline<0)break;const line=input.subarray(0,newline);input=input.subarray(newline+1);if(!line.length||line.length>MAX_INPUT){gap=true;finish(false);return;}let value;try{const text=line.toString("utf8");if(!Buffer.from(text,"utf8").equals(line))throw new Error("utf8");value=JSON.parse(text);}catch(_){gap=true;finish(false);return;}command(value);if(finished)return;}}
process.stdin.on("data",chunk=>{if(finished)return;if(input.length+chunk.length>MAX_INPUT){gap=true;finish(false);return;}input=Buffer.concat([input,chunk]);consume();});
process.stdin.on("end",()=>{if(!finished){gap=true;finish(false);}});
process.stdin.on("error",()=>{if(!finished){gap=true;finish(false);}});`

const pythonPeerPortObserverScript = `import hashlib,hmac,ipaddress,json,os,select,struct,sys,time
MAX_INPUT=2048;MAX_FILE=65536;MAX_LINES=4096;MAX_ENDPOINTS=16;MAX_TRANSITIONS=4096;MAX_CANONICAL=1048576
NS=("net","pid","mnt","ipc","cgroup");adapter="python-proc-net-tcp-linux";token="";session_digest="";interval=100;max_samples=1200;max_gap=1000;samples=transitions=max_observed_gap=canonical_bytes=0;last_ns=0;previous=set();observed=set();initial=[];final_endpoints=[];declared=[];declared_set=set();declared_observed=set();overflow=gap=finished=False;mac=None
def emit(value):
    sys.stdout.write(json.dumps(value,separators=(",",":"),sort_keys=True)+"\n");sys.stdout.flush()
def exact(value,keys):
    return isinstance(value,dict) and set(value)==set(keys)
def read(name,limit):
    with open(name,"rb") as source:value=source.read(limit+1)
    if len(value)>limit:raise ValueError()
    return value.decode("ascii")
def namespaces():
    result={}
    for name in NS:
        value=os.readlink("/proc/self/ns/"+name)
        if not value.startswith(name+":[") or not value.endswith("]") or not value[len(name)+2:-1].isdigit():raise ValueError()
        result[name]=value
    return result
def security():
    lines=read("/proc/self/status",16384).splitlines()
    def one(name):
        values=[line[len(name)+1:].strip() for line in lines if line.startswith(name+":")]
        if len(values)!=1:raise ValueError()
        return values[0]
    cap_eff=one("CapEff");no_new=one("NoNewPrivs");uids=one("Uid").split()
    if len(cap_eff)!=16 or any(ch!="0" for ch in cap_eff) or no_new!="1" or uids!=["65534"]*4:raise ValueError()
    return {"capEff":cap_eff,"noNewPrivs":True,"uid":65534}
def address(raw,v6):
    if len(raw)!=(32 if v6 else 8) or any(ch not in "0123456789ABCDEF" for ch in raw):raise ValueError()
    packed=bytes.fromhex(raw)
    if v6:packed=b"".join(packed[index:index+4][::-1] for index in range(0,16,4))
    else:packed=packed[::-1]
    return str(ipaddress.ip_address(packed))
def table(name,v6):
    lines=read(name,MAX_FILE).rstrip("\n").splitlines()
    if not lines or len(lines)>MAX_LINES or "local_address" not in lines[0]:raise ValueError()
    result=[]
    for line in lines[1:]:
        fields=line.split()
        if len(fields)<4 or len(fields[3])!=2 or any(ch not in "0123456789ABCDEF" for ch in fields[3]):raise ValueError()
        if fields[3]!="0A":continue
        local=fields[1].split(":")
        if len(local)!=2 or len(local[1])!=4 or any(ch not in "0123456789ABCDEF" for ch in local[1]):raise ValueError()
        port=int(local[1],16)
        if port<1 or port>65535:raise ValueError()
        host=address(local[0],v6);result.append(("["+host+"]" if v6 else host)+":"+str(port)+"/tcp")
    return result
def snapshot():
    result=sorted(set(table("/proc/net/tcp",False)+table("/proc/net/tcp6",True)))
    if len(result)>MAX_ENDPOINTS:raise ValueError()
    return result
def capture(boundary):
    global last_ns,samples,transitions,max_observed_gap,canonical_bytes,previous,initial,final_endpoints,overflow,gap
    if finished:return False
    now=time.monotonic_ns()
    if last_ns:
        observed_gap=(now-last_ns+999999)//1000000;max_observed_gap=max(max_observed_gap,observed_gap)
        if observed_gap>max_gap:gap=True;finish(False);return False
    last_ns=now;samples+=1
    if samples>max_samples:overflow=True;finish(False);return False
    try:values=snapshot()
    except Exception:gap=True;finish(False);return False
    current=set(values)
    if samples>1:
        transitions+=len(current-previous)+len(previous-current)
        if transitions>MAX_TRANSITIONS:overflow=True;finish(False);return False
    observed.update(current);declared_observed.update(current&declared_set)
    if len(observed)>MAX_ENDPOINTS:overflow=True;finish(False);return False
    if boundary=="initial":initial=values
    if boundary=="final":final_endpoints=values
    line=(json.dumps([samples,values],separators=(",",":"))+"\n").encode()
    if canonical_bytes+len(line)>MAX_CANONICAL:overflow=True;finish(False);return False
    mac.update(line);canonical_bytes+=len(line);previous=current;return True
def finish(ok):
    global finished,gap
    if finished:return
    if ok and not capture("final"):return
    finished=True
    try:ns=namespaces();sec=security()
    except Exception:gap=True;ns={};sec={"capEff":"","noNewPrivs":False,"uid":0}
    final_set=set(final_endpoints);closed=[value for value in declared if value in declared_observed and value not in final_set]
    emit({"type":"final","schemaVersion":"1","sessionDigest":session_digest,"ok":bool(ok and not overflow and not gap),"observerAdapter":adapter,"namespaces":ns,"capEff":sec["capEff"],"noNewPrivs":sec["noNewPrivs"],"uid":sec["uid"],"sampleCount":min(samples,max_samples),"intervalMillis":interval,"maxSampleGapMillis":max_observed_gap,"transitionCount":min(transitions,MAX_TRANSITIONS),"observedEndpoints":sorted(observed),"initialEndpoints":initial,"finalEndpoints":final_endpoints,"declaredEndpoints":declared,"declaredObservedEndpoints":[value for value in declared if value in declared_observed],"declaredClosedEndpoints":closed,"canonicalSampleDigest":"sha256:"+mac.hexdigest(),"canonicalByteCount":canonical_bytes,"overflowDetected":overflow,"gapDetected":gap})
def valid_start(value):
    return exact(value,("command","token","intervalMillis","maxSamples","maxGapMillis","declaredEndpoints")) and value.get("command")=="start" and isinstance(value.get("token"),str) and len(value["token"])==64 and all(ch in "0123456789abcdef" for ch in value["token"]) and value.get("intervalMillis")==100 and value.get("maxSamples")==1200 and value.get("maxGapMillis")==1000 and isinstance(value.get("declaredEndpoints"),list) and len(value["declaredEndpoints"])<=MAX_ENDPOINTS and all(isinstance(item,str) and len(item)<=64 and (index==0 or value["declaredEndpoints"][index-1]<item) for index,item in enumerate(value["declaredEndpoints"]))
line=sys.stdin.buffer.readline(MAX_INPUT+1)
try:start=json.loads(line)
except Exception:start=None
if len(line)>MAX_INPUT or not valid_start(start):sys.exit(1)
token=start["token"];session_digest="sha256:"+hashlib.sha256(token.encode("ascii")).hexdigest();interval=start["intervalMillis"];max_samples=start["maxSamples"];max_gap=start["maxGapMillis"];declared=start["declaredEndpoints"];declared_set=set(declared);mac=hmac.new(token.encode("ascii"),digestmod=hashlib.sha256)
try:ns=namespaces();sec=security()
except Exception:sys.exit(1)
if not capture("initial"):sys.exit(1)
emit({"type":"ready","schemaVersion":"1","sessionDigest":session_digest,"observerAdapter":adapter,"initialSampleComplete":True,"namespaces":ns,"capEff":sec["capEff"],"noNewPrivs":sec["noNewPrivs"],"uid":sec["uid"]})
control=b"";next_sample=time.monotonic()+interval/1000
while not finished:
    timeout=max(0,next_sample-time.monotonic());readable,_,_=select.select([sys.stdin.buffer],[],[],timeout)
    if readable:
        chunk=os.read(0,MAX_INPUT+1)
        if not chunk:gap=True;finish(False);break
        if len(control)+len(chunk)>MAX_INPUT:gap=True;finish(False);break
        control+=chunk
        while b"\n" in control and not finished:
            raw,control=control.split(b"\n",1)
            try:value=json.loads(raw)
            except Exception:value=None
            if not exact(value,("command","token")) or value.get("command")!="stop" or value.get("token")!=token:gap=True;finish(False);break
            finish(True)
    elif not capture("poll"):break
    next_sample=time.monotonic()+interval/1000
sys.exit(0 if finished and not gap and not overflow else 1)`

const (
	nodeTargetNamespaceScript   = `const fs=require("node:fs"),names=["net","pid","mnt","ipc","cgroup"],value={};for(const name of names)value[name]=fs.readlinkSync("/proc/self/ns/"+name);process.stdout.write(JSON.stringify(value)+"\n");`
	pythonTargetNamespaceScript = `import json,os
print(json.dumps({name:os.readlink("/proc/self/ns/"+name) for name in ("net","pid","mnt","ipc","cgroup")},separators=(",",":"),sort_keys=True))`
)

type peerPortNamespaces struct {
	Net    string
	PID    string
	Mount  string
	IPC    string
	Cgroup string
}

type peerPortReadyFrame struct {
	Type          string
	SchemaVersion string
	SessionDigest string
	Adapter       string
	Namespaces    peerPortNamespaces
	CapEff        string
	NoNewPrivs    bool
	UID           int
}

type peerPortResult struct {
	Adapter                   string
	Namespaces                peerPortNamespaces
	CapEff                    string
	NoNewPrivs                bool
	UID                       int
	SampleCount               int
	IntervalMillis            int
	MaxSampleGapMillis        int
	TransitionCount           int
	ObservedEndpoints         []string
	InitialEndpoints          []string
	FinalEndpoints            []string
	DeclaredEndpoints         []string
	DeclaredObservedEndpoints []string
	DeclaredClosedEndpoints   []string
	CanonicalSampleDigest     string
	CanonicalByteCount        int
	OverflowDetected          bool
	GapDetected               bool
}

type peerPortObservationState struct {
	required                   bool
	backendEligible            bool
	startAttempted             bool
	targetID                   string
	peerID                     string
	session                    *peerPortSession
	declaredEndpoints          []string
	startIdentityVerified      bool
	readyIdentityVerified      bool
	finalIdentityVerified      bool
	namespaceIsolationVerified bool
	workloadQuiescenceVerified bool
	peerRemoveVerified         bool
	ready                      bool
	finalReady                 bool
	result                     peerPortResult
	failure                    string
	observedAt                 time.Time
}

type peerPortDeclarationComparison struct {
	Result                  string
	DeclaredEndpointCount   int
	BaselineEndpointCount   int
	SampledEndpointCount    int
	UndeclaredEndpointCount int
}

type peerPortSession struct {
	token             string
	sessionDigest     string
	expectedAdapter   string
	declaredEndpoints []string
	readyNamespaces   peerPortNamespaces
	targetNamespaces  peerPortNamespaces
	process           RunningCommand
	stdin             io.WriteCloser
	stream            *activityTraceFrameStream
	stderr            *activityTraceLockedBuffer
	cancel            context.CancelFunc
	wait              <-chan activityTraceProcessResult
	controlMu         sync.Mutex
	abortOnce         sync.Once
	abortDone         chan struct{}
}

type peerPortTargetIdentity struct {
	ID             string
	RunLabel       string
	ImageReference string
	Running        bool
}

type peerPortContainerIdentity struct {
	ID             string
	RunLabel       string
	ObserverLabel  string
	ImageReference string
	NetworkMode    string
	PIDMode        string
	IPCMode        string
	CgroupnsMode   string
	User           string
	ReadOnlyRootfs bool
	MemoryBytes    int64
	MemorySwap     int64
	PIDsLimit      int
	NanoCPUs       int64
	CapDrop        []string
	SecurityOpt    []string
	Privileged     bool
	CapAdd         []string
	Binds          []string
	Mounts         []json.RawMessage
	Devices        []json.RawMessage
	PortBindings   map[string]json.RawMessage
	Running        bool
}

func securePeerPortToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func peerPortSessionDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return fmt.Sprintf("sha256:%x", digest)
}

func planRequiresPortObservation(plan domain.ResolvedPlan) bool {
	for _, observer := range plan.ObserverSet {
		if observer == "port-listen" {
			return true
		}
	}
	if _, ok := plan.ObserverVersions["port-listen"]; ok {
		return true
	}
	for _, feature := range plan.RequiredRunnerFeatures {
		switch feature {
		case "port-listen-observation", "observer:port-listen":
			return true
		}
	}
	return false
}

func declaredPeerPortEndpoints(
	plan domain.ResolvedPlan,
) ([]string, error) {
	if plan.HTTPJourney == nil || plan.JourneyDriver != "http" {
		return nil, errors.New("port observer requires the supported HTTP profile")
	}
	capability, ok := plan.Capabilities[domain.PhaseRun]
	if !ok || len(capability.Ports.Listen) != 1 {
		return nil, errors.New("port observer requires one declared run listener")
	}
	binding := capability.Ports.Listen[0]
	if binding.Host != "127.0.0.1" || binding.Protocol != "tcp" ||
		binding.Port < 1 || binding.Port > 65535 {
		return nil, errors.New("port observer requires one canonical loopback TCP listener")
	}
	var serviceCount int
	var service *domain.PlanCommand
	var signalCount int
	for index := range plan.Commands {
		command := &plan.Commands[index]
		switch command.Role {
		case "service":
			serviceCount++
			service = command
		case "signal":
			signalCount++
		}
	}
	if serviceCount != 1 || signalCount != 1 || service == nil ||
		service.ID != plan.HTTPJourney.ServiceID || service.Readiness == nil {
		return nil, errors.New("port observer requires one sealed service lifecycle")
	}
	_, readinessPort, err := domain.ParseAlphaHTTPURL(service.Readiness.URL)
	if err != nil || readinessPort != binding.Port {
		return nil, errors.New("port observer service origin does not match the declared listener")
	}
	if plan.RuntimeAdapter != "node" && plan.RuntimeAdapter != "python" {
		return nil, errors.New("port observer runtime adapter is unsupported")
	}
	return []string{
		fmt.Sprintf("127.0.0.1:%d/tcp", binding.Port),
	}, nil
}

func canonicalPeerPortEndpoint(value string) (string, error) {
	if !strings.HasSuffix(value, "/tcp") {
		return "", errors.New("port endpoint protocol is invalid")
	}
	addressPort, err := netip.ParseAddrPort(
		strings.TrimSuffix(value, "/tcp"),
	)
	if err != nil || !addressPort.IsValid() || addressPort.Port() == 0 {
		return "", errors.New("port endpoint address is invalid")
	}
	address := addressPort.Addr()
	var canonical string
	if address.Is4() {
		canonical = fmt.Sprintf(
			"%s:%d/tcp",
			address.String(),
			addressPort.Port(),
		)
	} else {
		canonical = fmt.Sprintf(
			"[%s]:%d/tcp",
			address.String(),
			addressPort.Port(),
		)
	}
	if canonical != value {
		return "", errors.New("port endpoint is not canonical")
	}
	return canonical, nil
}

func validatePeerPortEndpointList(values []string) error {
	if len(values) > peerPortEndpointLimit {
		return errors.New("port endpoint list exceeds its bound")
	}
	for index, value := range values {
		if len(value) == 0 || len(value) > 64 {
			return errors.New("port endpoint length is invalid")
		}
		if _, err := canonicalPeerPortEndpoint(value); err != nil {
			return err
		}
		if index > 0 && values[index-1] >= value {
			return errors.New("port endpoint list is not strictly sorted")
		}
	}
	return nil
}

func samePeerPortEndpoints(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func completePeerPortObservation(state peerPortObservationState) bool {
	identityVerified := state.startIdentityVerified &&
		state.readyIdentityVerified &&
		state.finalIdentityVerified
	if !state.required || !state.backendEligible || state.failure != "" ||
		!identityVerified || !state.namespaceIsolationVerified ||
		!state.workloadQuiescenceVerified || !state.peerRemoveVerified ||
		!state.ready || !state.finalReady ||
		state.result.OverflowDetected || state.result.GapDetected ||
		len(state.result.InitialEndpoints) != 0 ||
		len(state.declaredEndpoints) != 1 {
		return false
	}
	lists := [][]string{
		state.result.ObservedEndpoints,
		state.result.InitialEndpoints,
		state.result.FinalEndpoints,
		state.result.DeclaredEndpoints,
		state.result.DeclaredObservedEndpoints,
		state.result.DeclaredClosedEndpoints,
		state.declaredEndpoints,
	}
	for _, list := range lists {
		if validatePeerPortEndpointList(list) != nil {
			return false
		}
	}
	return samePeerPortEndpoints(
		state.result.DeclaredEndpoints,
		state.declaredEndpoints,
	) && samePeerPortEndpoints(
		state.result.DeclaredObservedEndpoints,
		state.declaredEndpoints,
	) && samePeerPortEndpoints(
		state.result.DeclaredClosedEndpoints,
		state.declaredEndpoints,
	) && peerPortEndpointSubset(
		state.result.InitialEndpoints,
		state.result.ObservedEndpoints,
	) && peerPortEndpointSubset(
		state.result.FinalEndpoints,
		state.result.ObservedEndpoints,
	) && peerPortEndpointSubset(
		state.result.DeclaredObservedEndpoints,
		state.result.ObservedEndpoints,
	) && peerPortEndpointsDisjoint(
		state.declaredEndpoints,
		state.result.InitialEndpoints,
	) && peerPortEndpointsDisjoint(
		state.declaredEndpoints,
		state.result.FinalEndpoints,
	)
}

func comparePeerPortDeclarations(
	state peerPortObservationState,
) peerPortDeclarationComparison {
	comparison := peerPortDeclarationComparison{
		Result: peerPortComparisonUntested,
	}
	if !completePeerPortObservation(state) {
		return comparison
	}
	comparison.DeclaredEndpointCount = len(state.declaredEndpoints)
	comparison.BaselineEndpointCount = len(state.result.InitialEndpoints)
	comparison.SampledEndpointCount = len(state.result.ObservedEndpoints)

	baseline := make(map[string]struct{}, len(state.result.InitialEndpoints))
	for _, endpoint := range state.result.InitialEndpoints {
		baseline[endpoint] = struct{}{}
	}
	declared := make(map[string]struct{}, len(state.declaredEndpoints))
	for _, endpoint := range state.declaredEndpoints {
		declared[endpoint] = struct{}{}
	}
	for _, endpoint := range state.result.ObservedEndpoints {
		if _, existedAtBaseline := baseline[endpoint]; existedAtBaseline {
			continue
		}
		if _, allowed := declared[endpoint]; !allowed {
			comparison.UndeclaredEndpointCount++
		}
	}
	comparison.Result = peerPortComparisonNegative
	if comparison.UndeclaredEndpointCount > 0 {
		comparison.Result = peerPortComparisonPositive
	}
	return comparison
}

func peerPortDeclarationFinding(
	comparison peerPortDeclarationComparison,
) *domain.Error {
	if comparison.Result != peerPortComparisonPositive ||
		comparison.UndeclaredEndpointCount < 1 {
		return nil
	}
	err := domain.NewError(
		domain.CodeUndeclaredPortListen,
		domain.SeverityHigh,
		"Bounded peer TCP samples observed one or more listeners outside the declared service endpoint.",
	)
	err.Details = map[string]any{
		"observer":                "docker-peer-port-listener-trace",
		"evidenceBasis":           "aggregate-only",
		"undeclaredEndpointCount": comparison.UndeclaredEndpointCount,
	}
	return err
}

func peerPortEndpointSubset(subset, superset []string) bool {
	available := make(map[string]struct{}, len(superset))
	for _, value := range superset {
		available[value] = struct{}{}
	}
	for _, value := range subset {
		if _, ok := available[value]; !ok {
			return false
		}
	}
	return true
}

func peerPortEndpointsDisjoint(first, second []string) bool {
	available := make(map[string]struct{}, len(second))
	for _, value := range second {
		available[value] = struct{}{}
	}
	for _, value := range first {
		if _, ok := available[value]; ok {
			return false
		}
	}
	return true
}

func parseProcNetTCPTable(raw []byte, ipv6 bool) ([]string, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) {
		return nil, errors.New("proc TCP table is invalid")
	}
	for _, value := range raw {
		if value != '\n' && value != '\r' && value != '\t' &&
			(value < 0x20 || value > 0x7e) {
			return nil, errors.New("proc TCP table is not ASCII")
		}
	}
	lines := strings.Split(strings.TrimSuffix(
		strings.TrimSuffix(string(raw), "\n"),
		"\r",
	), "\n")
	if len(lines) == 0 || len(lines) > 4096 ||
		!strings.Contains(lines[0], "local_address") {
		return nil, errors.New("proc TCP table header is invalid")
	}
	result := make([]string, 0)
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			return nil, errors.New("proc TCP table contains an empty row")
		}
		fields := strings.Fields(line)
		if len(fields) < 4 || len(fields[3]) != 2 ||
			!allUpperHex(fields[3]) {
			return nil, errors.New("proc TCP table row is invalid")
		}
		if fields[3] != "0A" {
			continue
		}
		local := strings.Split(fields[1], ":")
		if len(local) != 2 || len(local[1]) != 4 ||
			!allUpperHex(local[1]) {
			return nil, errors.New("proc TCP local address is invalid")
		}
		portValue, err := strconv.ParseUint(local[1], 16, 16)
		if err != nil || portValue == 0 {
			return nil, errors.New("proc TCP local port is invalid")
		}
		address, err := decodeProcNetTCPAddress(local[0], ipv6)
		if err != nil {
			return nil, err
		}
		if ipv6 {
			result = append(
				result,
				fmt.Sprintf(
					"[%s]:%d/tcp",
					address.String(),
					portValue,
				),
			)
		} else {
			result = append(
				result,
				fmt.Sprintf(
					"%s:%d/tcp",
					address.String(),
					portValue,
				),
			)
		}
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, errors.New("proc TCP table contains a duplicate listener")
		}
	}
	if len(result) > peerPortEndpointLimit {
		return nil, errors.New("proc TCP listener set exceeds its bound")
	}
	return result, nil
}

func allUpperHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'A' || character > 'F' {
				return false
			}
		}
	}
	return true
}

func decodeProcNetTCPAddress(value string, ipv6 bool) (netip.Addr, error) {
	expected := 8
	if ipv6 {
		expected = 32
	}
	if len(value) != expected || !allUpperHex(value) {
		return netip.Addr{}, errors.New("proc TCP address is invalid")
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return netip.Addr{}, errors.New("proc TCP address is invalid")
	}
	if !ipv6 {
		var address [4]byte
		for index := range address {
			address[index] = raw[len(raw)-1-index]
		}
		return netip.AddrFrom4(address), nil
	}
	var address [16]byte
	for word := 0; word < len(raw); word += 4 {
		for index := 0; index < 4; index++ {
			address[word+index] = raw[word+3-index]
		}
	}
	return netip.AddrFrom16(address), nil
}

func decodePeerPortNamespaces(
	raw json.RawMessage,
) (peerPortNamespaces, error) {
	fields, err := decodeActivityTraceObject(raw)
	if err != nil || !exactActivityTraceKeys(fields, []string{
		"net", "pid", "mnt", "ipc", "cgroup",
	}) {
		return peerPortNamespaces{}, errors.New(
			"port observer namespace frame is invalid",
		)
	}
	var result peerPortNamespaces
	values := []struct {
		key    string
		prefix string
		target *string
	}{
		{"net", "net:[", &result.Net},
		{"pid", "pid:[", &result.PID},
		{"mnt", "mnt:[", &result.Mount},
		{"ipc", "ipc:[", &result.IPC},
		{"cgroup", "cgroup:[", &result.Cgroup},
	}
	for _, value := range values {
		if decodeActivityTraceValue(fields[value.key], value.target) != nil ||
			!peerNamespacePattern.MatchString(*value.target) ||
			!strings.HasPrefix(*value.target, value.prefix) {
			return peerPortNamespaces{}, errors.New(
				"port observer namespace frame is invalid",
			)
		}
	}
	return result, nil
}

func samePeerPortNamespaces(
	first peerPortNamespaces,
	second peerPortNamespaces,
) bool {
	return first == second
}

func validatePeerPortNamespaceIsolation(
	peer peerPortNamespaces,
	target peerPortNamespaces,
) error {
	if peer.Net != target.Net {
		return errors.New("port observer does not share the target network namespace")
	}
	if peer.PID == target.PID || peer.Mount == target.Mount ||
		peer.IPC == target.IPC || peer.Cgroup == target.Cgroup {
		return errors.New("port observer shares a forbidden target namespace")
	}
	return nil
}

func decodePeerPortReadyFrame(
	raw []byte,
	expectedSessionDigest string,
	expectedAdapter string,
) (peerPortReadyFrame, error) {
	if len(raw) == 0 || len(raw) > peerPortFrameLimit {
		return peerPortReadyFrame{}, errors.New(
			"port observer ready frame is invalid",
		)
	}
	fields, err := decodeActivityTraceObject(raw)
	if err != nil || !exactActivityTraceKeys(fields, []string{
		"type", "schemaVersion", "sessionDigest", "observerAdapter",
		"initialSampleComplete", "namespaces", "capEff", "noNewPrivs",
		"uid",
	}) {
		return peerPortReadyFrame{}, errors.New(
			"port observer ready frame is invalid",
		)
	}
	var frame peerPortReadyFrame
	var initialSampleComplete bool
	values := []struct {
		key    string
		target any
	}{
		{"type", &frame.Type},
		{"schemaVersion", &frame.SchemaVersion},
		{"sessionDigest", &frame.SessionDigest},
		{"observerAdapter", &frame.Adapter},
		{"initialSampleComplete", &initialSampleComplete},
		{"capEff", &frame.CapEff},
		{"noNewPrivs", &frame.NoNewPrivs},
		{"uid", &frame.UID},
	}
	for _, value := range values {
		if decodeActivityTraceValue(
			fields[value.key],
			value.target,
		) != nil {
			return peerPortReadyFrame{}, errors.New(
				"port observer ready frame is invalid",
			)
		}
	}
	frame.Namespaces, err = decodePeerPortNamespaces(fields["namespaces"])
	if err != nil ||
		frame.Type != "ready" || frame.SchemaVersion != "1" ||
		frame.SessionDigest != expectedSessionDigest ||
		!peerPortDigestPattern.MatchString(frame.SessionDigest) ||
		frame.Adapter != expectedAdapter ||
		!validPeerPortAdapter(frame.Adapter) ||
		!initialSampleComplete ||
		!peerPortCapEffPattern.MatchString(frame.CapEff) ||
		!frame.NoNewPrivs || frame.UID != 65534 {
		return peerPortReadyFrame{}, errors.New(
			"port observer ready frame is invalid",
		)
	}
	return frame, nil
}

func decodePeerPortFinalFrame(
	raw []byte,
	expectedSessionDigest string,
	expectedAdapter string,
	expectedNamespaces peerPortNamespaces,
	expectedDeclared []string,
) (peerPortResult, error) {
	if len(raw) == 0 || len(raw) > peerPortFrameLimit {
		return peerPortResult{}, errors.New(
			"port observer final frame is invalid",
		)
	}
	if len(expectedDeclared) != 1 ||
		validatePeerPortEndpointList(expectedDeclared) != nil {
		return peerPortResult{}, errors.New(
			"port observer declared endpoint is invalid",
		)
	}
	fields, err := decodeActivityTraceObject(raw)
	if err != nil || !exactActivityTraceKeys(fields, []string{
		"type", "schemaVersion", "sessionDigest", "ok",
		"observerAdapter", "namespaces", "capEff", "noNewPrivs", "uid",
		"sampleCount", "intervalMillis", "maxSampleGapMillis",
		"transitionCount", "observedEndpoints", "initialEndpoints",
		"finalEndpoints", "declaredEndpoints",
		"declaredObservedEndpoints", "declaredClosedEndpoints",
		"canonicalSampleDigest", "canonicalByteCount",
		"overflowDetected", "gapDetected",
	}) {
		return peerPortResult{}, errors.New(
			"port observer final frame is invalid",
		)
	}
	var frameType, schemaVersion, sessionDigest string
	var ok bool
	result := peerPortResult{}
	values := []struct {
		key    string
		target any
	}{
		{"type", &frameType},
		{"schemaVersion", &schemaVersion},
		{"sessionDigest", &sessionDigest},
		{"ok", &ok},
		{"observerAdapter", &result.Adapter},
		{"capEff", &result.CapEff},
		{"noNewPrivs", &result.NoNewPrivs},
		{"uid", &result.UID},
		{"sampleCount", &result.SampleCount},
		{"intervalMillis", &result.IntervalMillis},
		{"maxSampleGapMillis", &result.MaxSampleGapMillis},
		{"transitionCount", &result.TransitionCount},
		{"observedEndpoints", &result.ObservedEndpoints},
		{"initialEndpoints", &result.InitialEndpoints},
		{"finalEndpoints", &result.FinalEndpoints},
		{"declaredEndpoints", &result.DeclaredEndpoints},
		{"declaredObservedEndpoints", &result.DeclaredObservedEndpoints},
		{"declaredClosedEndpoints", &result.DeclaredClosedEndpoints},
		{"canonicalSampleDigest", &result.CanonicalSampleDigest},
		{"canonicalByteCount", &result.CanonicalByteCount},
		{"overflowDetected", &result.OverflowDetected},
		{"gapDetected", &result.GapDetected},
	}
	for _, value := range values {
		if decodeActivityTraceValue(
			fields[value.key],
			value.target,
		) != nil {
			return peerPortResult{}, errors.New(
				"port observer final frame is invalid",
			)
		}
	}
	result.Namespaces, err = decodePeerPortNamespaces(fields["namespaces"])
	if err != nil {
		return peerPortResult{}, errors.New(
			"port observer final frame is invalid",
		)
	}
	lists := [][]string{
		result.ObservedEndpoints,
		result.InitialEndpoints,
		result.FinalEndpoints,
		result.DeclaredEndpoints,
		result.DeclaredObservedEndpoints,
		result.DeclaredClosedEndpoints,
	}
	for _, list := range lists {
		if err := validatePeerPortEndpointList(list); err != nil {
			return peerPortResult{}, errors.New(
				"port observer final endpoint set is invalid",
			)
		}
	}
	if frameType != "final" || schemaVersion != "1" ||
		sessionDigest != expectedSessionDigest ||
		result.Adapter != expectedAdapter ||
		!validPeerPortAdapter(result.Adapter) ||
		!samePeerPortNamespaces(
			result.Namespaces,
			expectedNamespaces,
		) ||
		!peerPortCapEffPattern.MatchString(result.CapEff) ||
		!result.NoNewPrivs || result.UID != 65534 ||
		result.SampleCount < 3 ||
		result.SampleCount > peerPortSampleLimit ||
		result.IntervalMillis != peerPortIntervalMillis ||
		result.MaxSampleGapMillis < 0 ||
		result.MaxSampleGapMillis > peerPortMaxGapMillis ||
		result.TransitionCount < 0 ||
		result.TransitionCount > peerPortTransitionLimit ||
		result.TransitionCount < 2*len(expectedDeclared) ||
		!peerPortDigestPattern.MatchString(
			result.CanonicalSampleDigest,
		) ||
		result.CanonicalByteCount <= 0 ||
		result.CanonicalByteCount > peerPortCanonicalLimit ||
		!samePeerPortEndpoints(
			result.DeclaredEndpoints,
			expectedDeclared,
		) ||
		!samePeerPortEndpoints(
			result.DeclaredObservedEndpoints,
			expectedDeclared,
		) ||
		!samePeerPortEndpoints(
			result.DeclaredClosedEndpoints,
			expectedDeclared,
		) ||
		!peerPortEndpointSubset(
			result.InitialEndpoints,
			result.ObservedEndpoints,
		) ||
		!peerPortEndpointSubset(
			result.FinalEndpoints,
			result.ObservedEndpoints,
		) ||
		!peerPortEndpointSubset(
			result.DeclaredObservedEndpoints,
			result.ObservedEndpoints,
		) ||
		!peerPortEndpointsDisjoint(
			expectedDeclared,
			result.InitialEndpoints,
		) ||
		!peerPortEndpointsDisjoint(
			expectedDeclared,
			result.FinalEndpoints,
		) ||
		!ok || result.OverflowDetected || result.GapDetected {
		return peerPortResult{}, errors.New(
			"port observer final frame is incomplete",
		)
	}
	return result, nil
}

func validPeerPortAdapter(value string) bool {
	return value == "node-proc-net-tcp-linux" ||
		value == "python-proc-net-tcp-linux"
}

func buildPeerPortCreateArgs(
	prepared *PreparedRun,
	targetID string,
) (string, []string, string, error) {
	if prepared == nil || prepared.Backend != "docker" ||
		!safeRunID(prepared.RunID) ||
		!fullContainerIDPattern.MatchString(targetID) ||
		prepared.Platform == "" {
		return "", nil, "", errors.New(
			"port observer has no trusted target binding",
		)
	}
	executable, ok := runtimeExecutable(
		prepared.executionPlan.RuntimeAdapter,
	)
	if !ok {
		return "", nil, "", errors.New(
			"port observer runtime helper is unavailable",
		)
	}
	scriptArgs := []string{"-e", nodePeerPortObserverScript}
	adapter := "node-proc-net-tcp-linux"
	if prepared.executionPlan.RuntimeAdapter == "python" {
		scriptArgs = []string{
			"-I", "-S", "-c", pythonPeerPortObserverScript,
		}
		adapter = "python-proc-net-tcp-linux"
	}
	name := peerPortNamePrefix + prepared.RunID
	args := []string{
		"create", "--interactive",
		"--name", name,
		"--label", runLabelKey + "=" + prepared.RunID,
		"--label", peerPortObserverLabelKey + "=" +
			peerPortObserverLabelValue,
		"--platform", prepared.Platform,
		"--network", "container:" + targetID,
		"--ipc", "none",
		"--cgroupns", "private",
		"--user", "65534:65534",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges=true",
		"--pids-limit", strconv.Itoa(peerPortPIDsLimit),
		"--memory", strconv.FormatInt(peerPortMemoryBytes, 10),
		"--memory-swap", strconv.FormatInt(peerPortMemoryBytes, 10),
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
		"--entrypoint", executable,
		prepared.executionPlan.BaseImageReference,
	}
	args = append(args, scriptArgs...)
	return name, args, adapter, nil
}

func decodePeerPortTargetIdentity(
	raw []byte,
) (peerPortTargetIdentity, error) {
	fields, err := decodeActivityTraceObject(raw)
	if err != nil || !exactActivityTraceKeys(fields, []string{
		"id", "runLabel", "imageReference", "running",
	}) {
		return peerPortTargetIdentity{}, errors.New(
			"port observer target identity is invalid",
		)
	}
	var identity peerPortTargetIdentity
	values := []struct {
		key    string
		target any
	}{
		{"id", &identity.ID},
		{"runLabel", &identity.RunLabel},
		{"imageReference", &identity.ImageReference},
		{"running", &identity.Running},
	}
	for _, value := range values {
		if decodeActivityTraceValue(
			fields[value.key],
			value.target,
		) != nil {
			return peerPortTargetIdentity{}, errors.New(
				"port observer target identity is invalid",
			)
		}
	}
	if !fullContainerIDPattern.MatchString(identity.ID) ||
		identity.RunLabel == "" || identity.ImageReference == "" {
		return peerPortTargetIdentity{}, errors.New(
			"port observer target identity is incomplete",
		)
	}
	return identity, nil
}

func decodePeerPortContainerIdentity(
	raw []byte,
) (peerPortContainerIdentity, error) {
	fields, err := decodeActivityTraceObject(raw)
	if err != nil || !exactActivityTraceKeys(fields, []string{
		"id", "runLabel", "observerLabel", "imageReference",
		"networkMode", "pidMode", "ipcMode", "cgroupnsMode", "user",
		"readOnlyRootfs", "memoryBytes", "memorySwap", "pidsLimit",
		"nanoCPUs", "capDrop", "securityOpt", "privileged",
		"capAdd", "binds", "mounts", "devices", "portBindings", "running",
	}) {
		return peerPortContainerIdentity{}, errors.New(
			"port observer peer identity is invalid",
		)
	}
	var identity peerPortContainerIdentity
	values := []struct {
		key    string
		target any
	}{
		{"id", &identity.ID},
		{"runLabel", &identity.RunLabel},
		{"observerLabel", &identity.ObserverLabel},
		{"imageReference", &identity.ImageReference},
		{"networkMode", &identity.NetworkMode},
		{"pidMode", &identity.PIDMode},
		{"ipcMode", &identity.IPCMode},
		{"cgroupnsMode", &identity.CgroupnsMode},
		{"user", &identity.User},
		{"readOnlyRootfs", &identity.ReadOnlyRootfs},
		{"memoryBytes", &identity.MemoryBytes},
		{"memorySwap", &identity.MemorySwap},
		{"pidsLimit", &identity.PIDsLimit},
		{"nanoCPUs", &identity.NanoCPUs},
		{"capDrop", &identity.CapDrop},
		{"securityOpt", &identity.SecurityOpt},
		{"privileged", &identity.Privileged},
		{"running", &identity.Running},
	}
	for _, value := range values {
		if decodeActivityTraceValue(
			fields[value.key],
			value.target,
		) != nil {
			return peerPortContainerIdentity{}, errors.New(
				"port observer peer identity is invalid",
			)
		}
	}
	collections := []struct {
		key    string
		target any
	}{
		{"capAdd", &identity.CapAdd},
		{"binds", &identity.Binds},
		{"mounts", &identity.Mounts},
		{"devices", &identity.Devices},
		{"portBindings", &identity.PortBindings},
	}
	for _, collection := range collections {
		raw := fields[collection.key]
		if strings.TrimSpace(string(raw)) == "null" {
			continue
		}
		if decodeActivityTraceValue(raw, collection.target) != nil {
			return peerPortContainerIdentity{}, errors.New(
				"port observer peer identity is invalid",
			)
		}
	}
	if !fullContainerIDPattern.MatchString(identity.ID) {
		return peerPortContainerIdentity{}, errors.New(
			"port observer peer identity is incomplete",
		)
	}
	return identity, nil
}

func validatePeerPortTargetIdentity(
	identity peerPortTargetIdentity,
	prepared *PreparedRun,
	targetID string,
	expectedRunning bool,
) error {
	if prepared == nil ||
		identity.ID != targetID ||
		identity.RunLabel != prepared.RunID ||
		identity.ImageReference !=
			prepared.executionPlan.BaseImageReference ||
		identity.Running != expectedRunning {
		return errors.New("port observer target identity changed")
	}
	return nil
}

func validatePeerPortContainerIdentity(
	identity peerPortContainerIdentity,
	prepared *PreparedRun,
	targetID string,
	expectedID string,
	expectedRunning *bool,
) error {
	if prepared == nil ||
		(expectedID != "" && identity.ID != expectedID) ||
		identity.RunLabel != prepared.RunID ||
		identity.ObserverLabel != peerPortObserverLabelValue ||
		identity.ImageReference !=
			prepared.executionPlan.BaseImageReference ||
		identity.NetworkMode != "container:"+targetID ||
		identity.PIDMode != "" ||
		identity.IPCMode != "none" ||
		identity.CgroupnsMode != "private" ||
		identity.User != "65534:65534" ||
		!identity.ReadOnlyRootfs ||
		identity.MemoryBytes != peerPortMemoryBytes ||
		identity.MemorySwap != peerPortMemoryBytes ||
		identity.PIDsLimit != peerPortPIDsLimit ||
		identity.NanoCPUs != peerPortNanoCPUs ||
		len(identity.CapDrop) != 1 ||
		identity.CapDrop[0] != "ALL" ||
		len(identity.SecurityOpt) != 1 ||
		(identity.SecurityOpt[0] != "no-new-privileges" &&
			identity.SecurityOpt[0] != "no-new-privileges=true") ||
		identity.Privileged ||
		len(identity.CapAdd) != 0 ||
		len(identity.Binds) != 0 ||
		len(identity.Mounts) != 0 ||
		len(identity.Devices) != 0 ||
		len(identity.PortBindings) != 0 ||
		expectedRunning != nil &&
			identity.Running != *expectedRunning {
		return errors.New("port observer peer security identity changed")
	}
	return nil
}

func (r *Runner) inspectPeerPortTargetIdentity(
	ctx context.Context,
	prepared *PreparedRun,
	targetID string,
	expectedRunning bool,
) error {
	if prepared == nil || prepared.Backend != "docker" ||
		!fullContainerIDPattern.MatchString(targetID) ||
		!safeRunID(prepared.RunID) {
		return errors.New("port observer target identity is unavailable")
	}
	stdout := &cappedBuffer{limit: peerPortControlLimit}
	stderr := &cappedBuffer{limit: peerPortControlLimit}
	exitCode, runErr := r.executor.Run(
		ctx,
		"docker",
		[]string{
			"inspect", "--type", "container", "--format",
			peerPortTargetIdentityFormat, targetID,
		},
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 ||
		stdout.truncated || stderr.truncated ||
		len(stderr.Bytes()) != 0 {
		return errors.New("port observer could not inspect the target")
	}
	identity, err := decodePeerPortTargetIdentity(stdout.Bytes())
	if err != nil {
		return err
	}
	return validatePeerPortTargetIdentity(
		identity,
		prepared,
		targetID,
		expectedRunning,
	)
}

func (r *Runner) inspectPeerPortContainerIdentity(
	ctx context.Context,
	prepared *PreparedRun,
	targetID string,
	reference string,
	expectedID string,
	expectedRunning *bool,
) (peerPortContainerIdentity, error) {
	if prepared == nil || prepared.Backend != "docker" ||
		!fullContainerIDPattern.MatchString(targetID) ||
		reference == "" || !safeRunID(prepared.RunID) {
		return peerPortContainerIdentity{}, errors.New(
			"port observer peer identity is unavailable",
		)
	}
	stdout := &cappedBuffer{limit: peerPortControlLimit}
	stderr := &cappedBuffer{limit: peerPortControlLimit}
	exitCode, runErr := r.executor.Run(
		ctx,
		"docker",
		[]string{
			"inspect", "--type", "container", "--format",
			peerPortContainerIdentityFormat, reference,
		},
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 ||
		stdout.truncated || stderr.truncated ||
		len(stderr.Bytes()) != 0 {
		return peerPortContainerIdentity{}, errors.New(
			"port observer could not inspect the peer",
		)
	}
	identity, err := decodePeerPortContainerIdentity(stdout.Bytes())
	if err != nil {
		return peerPortContainerIdentity{}, err
	}
	if err := validatePeerPortContainerIdentity(
		identity,
		prepared,
		targetID,
		expectedID,
		expectedRunning,
	); err != nil {
		return peerPortContainerIdentity{}, err
	}
	return identity, nil
}

func (r *Runner) collectPeerPortTargetNamespaces(
	ctx context.Context,
	prepared *PreparedRun,
	targetID string,
) (peerPortNamespaces, error) {
	if prepared == nil || prepared.Backend != "docker" ||
		!fullContainerIDPattern.MatchString(targetID) {
		return peerPortNamespaces{}, errors.New(
			"port observer target namespace identity is unavailable",
		)
	}
	executable, ok := runtimeExecutable(
		prepared.executionPlan.RuntimeAdapter,
	)
	if !ok {
		return peerPortNamespaces{}, errors.New(
			"port observer target namespace helper is unavailable",
		)
	}
	scriptArgs := []string{"-e", nodeTargetNamespaceScript}
	if prepared.executionPlan.RuntimeAdapter == "python" {
		scriptArgs = []string{
			"-I", "-S", "-c", pythonTargetNamespaceScript,
		}
	}
	args := []string{
		"exec", "--user", "0:0", "--workdir", "/",
		targetID, executable,
	}
	args = append(args, scriptArgs...)
	stdout := &cappedBuffer{limit: peerPortControlLimit}
	stderr := &cappedBuffer{limit: peerPortControlLimit}
	exitCode, runErr := r.executor.Run(
		ctx,
		"docker",
		args,
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 ||
		stdout.truncated || stderr.truncated ||
		len(stderr.Bytes()) != 0 {
		return peerPortNamespaces{}, errors.New(
			"port observer target namespace helper failed",
		)
	}
	return decodePeerPortNamespaces(stdout.Bytes())
}

func (r *Runner) recoverPeerPortContainerID(
	ctx context.Context,
	prepared *PreparedRun,
	targetID string,
	name string,
) string {
	identity, err := r.inspectPeerPortContainerIdentity(
		ctx,
		prepared,
		targetID,
		name,
		"",
		nil,
	)
	if err != nil {
		return ""
	}
	return identity.ID
}

func (r *Runner) startPeerPortObservation(
	ctx context.Context,
	prepared *PreparedRun,
	targetID string,
	declaredEndpoints []string,
) (*peerPortSession, string, error) {
	if prepared == nil || prepared.Backend != "docker" {
		return nil, "", errors.New("port observer backend is unavailable")
	}
	asyncExecutor, ok := r.executor.(AsyncCommandExecutor)
	if !ok {
		return nil, "", errors.New("port observer transport is unavailable")
	}
	if err := validatePeerPortEndpointList(declaredEndpoints); err != nil ||
		len(declaredEndpoints) != 1 {
		return nil, "", errors.New(
			"port observer declared endpoint is invalid",
		)
	}
	if err := r.inspectPeerPortTargetIdentity(
		ctx,
		prepared,
		targetID,
		true,
	); err != nil {
		return nil, "", err
	}
	name, createArgs, expectedAdapter, err :=
		buildPeerPortCreateArgs(prepared, targetID)
	if err != nil {
		return nil, "", err
	}
	createStdout := &cappedBuffer{limit: peerPortControlLimit}
	createStderr := &cappedBuffer{limit: peerPortControlLimit}
	createExit, createErr := r.executor.Run(
		ctx,
		"docker",
		createArgs,
		createStdout,
		createStderr,
	)
	if createErr != nil || createExit != 0 ||
		createStdout.truncated || createStderr.truncated ||
		len(createStderr.Bytes()) != 0 {
		recovered := r.recoverPeerPortContainerID(
			ctx,
			prepared,
			targetID,
			name,
		)
		return nil, recovered, errors.New(
			"port observer peer creation failed",
		)
	}
	peerID, err := parseCreatedContainerID(createStdout.Bytes())
	if err != nil {
		recovered := r.recoverPeerPortContainerID(
			ctx,
			prepared,
			targetID,
			name,
		)
		return nil, recovered, errors.New(
			"port observer peer identity is unavailable",
		)
	}
	stopped := false
	if _, err := r.inspectPeerPortContainerIdentity(
		ctx,
		prepared,
		targetID,
		peerID,
		peerID,
		&stopped,
	); err != nil {
		return nil, peerID, err
	}
	token, err := securePeerPortToken()
	if err != nil {
		return nil, peerID, errors.New(
			"port observer session could not be created",
		)
	}
	stream := newBoundedActivityTraceFrameStream(
		peerPortFrameLimit,
		peerPortTransportLimit,
		2,
	)
	stderr := &activityTraceLockedBuffer{limit: peerPortStderrLimit}
	lifetimeCtx, cancel := context.WithCancel(context.Background())
	process, err := asyncExecutor.Start(
		lifetimeCtx,
		"docker",
		[]string{
			"start", "--attach", "--interactive", peerID,
		},
		stream,
		stderr,
	)
	if err != nil || process == nil {
		cancel()
		return nil, peerID, errors.New(
			"port observer peer process did not start",
		)
	}
	stdin := process.Stdin()
	if stdin == nil {
		cancel()
		reapUnusableActivityTraceProcess(process)
		return nil, peerID, errors.New(
			"port observer peer stdin is unavailable",
		)
	}
	wait := make(chan activityTraceProcessResult, 1)
	go func() {
		exitCode, waitErr := process.Wait()
		wait <- activityTraceProcessResult{
			exitCode: exitCode,
			err:      waitErr,
		}
	}()
	session := &peerPortSession{
		token:             token,
		sessionDigest:     peerPortSessionDigest(token),
		expectedAdapter:   expectedAdapter,
		declaredEndpoints: cloneStrings(declaredEndpoints),
		process:           process,
		stdin:             stdin,
		stream:            stream,
		stderr:            stderr,
		cancel:            cancel,
		wait:              wait,
		abortDone:         make(chan struct{}),
	}
	if err := session.writeControl(ctx, map[string]any{
		"command":           "start",
		"token":             token,
		"intervalMillis":    peerPortIntervalMillis,
		"maxSamples":        peerPortSampleLimit,
		"maxGapMillis":      peerPortMaxGapMillis,
		"declaredEndpoints": declaredEndpoints,
	}); err != nil {
		session.abort()
		return nil, peerID, errors.New(
			"port observer start frame failed",
		)
	}
	frame, err := stream.next(ctx)
	if err != nil {
		session.abort()
		return nil, peerID, errors.New(
			"port observer ready frame is unavailable",
		)
	}
	ready, err := decodePeerPortReadyFrame(
		frame,
		session.sessionDigest,
		expectedAdapter,
	)
	if err != nil {
		session.abort()
		return nil, peerID, err
	}
	targetNamespaces, err := r.collectPeerPortTargetNamespaces(
		ctx,
		prepared,
		targetID,
	)
	if err != nil {
		session.abort()
		return nil, peerID, err
	}
	if err := validatePeerPortNamespaceIsolation(
		ready.Namespaces,
		targetNamespaces,
	); err != nil {
		session.abort()
		return nil, peerID, err
	}
	if err := r.inspectPeerPortTargetIdentity(
		ctx,
		prepared,
		targetID,
		true,
	); err != nil {
		session.abort()
		return nil, peerID, err
	}
	running := true
	if _, err := r.inspectPeerPortContainerIdentity(
		ctx,
		prepared,
		targetID,
		peerID,
		peerID,
		&running,
	); err != nil {
		session.abort()
		return nil, peerID, err
	}
	session.readyNamespaces = ready.Namespaces
	session.targetNamespaces = targetNamespaces
	return session, peerID, nil
}

func (s *peerPortSession) writeControl(
	ctx context.Context,
	value any,
) error {
	if s == nil || s.stdin == nil {
		return errors.New("port observer control is unavailable")
	}
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 ||
		len(raw) > peerPortControlLimit {
		return errors.New("port observer control is invalid")
	}
	raw = append(raw, '\n')
	written := make(chan error, 1)
	go func() {
		count, writeErr := s.stdin.Write(raw)
		if writeErr == nil && count != len(raw) {
			writeErr = io.ErrShortWrite
		}
		written <- writeErr
	}()
	select {
	case writeErr := <-written:
		if writeErr != nil {
			return errors.New("port observer control write failed")
		}
		return nil
	case <-ctx.Done():
		_ = s.stdin.Close()
		if s.cancel != nil {
			s.cancel()
		}
		timer := time.NewTimer(peerPortWriteJoinTimeout)
		defer timer.Stop()
		select {
		case <-written:
		case <-timer.C:
		}
		return errors.New("port observer control write failed")
	}
}

func (s *peerPortSession) finish(
	ctx context.Context,
) (peerPortResult, error) {
	if s == nil {
		return peerPortResult{}, errors.New(
			"port observer session is unavailable",
		)
	}
	if err := s.writeControl(ctx, map[string]string{
		"command": "stop",
		"token":   s.token,
	}); err != nil {
		s.abort()
		return peerPortResult{}, err
	}
	if err := s.stdin.Close(); err != nil {
		s.abort()
		return peerPortResult{}, errors.New(
			"port observer input did not close",
		)
	}
	frame, err := s.stream.next(ctx)
	if err != nil {
		s.abort()
		return peerPortResult{}, errors.New(
			"port observer final frame is unavailable",
		)
	}
	result, err := decodePeerPortFinalFrame(
		frame,
		s.sessionDigest,
		s.expectedAdapter,
		s.readyNamespaces,
		s.declaredEndpoints,
	)
	if err != nil {
		s.abort()
		return peerPortResult{}, err
	}
	select {
	case waited := <-s.wait:
		s.cancel()
		if waited.err != nil || waited.exitCode != 0 ||
			!s.stderr.clean() || !s.stream.complete() {
			return peerPortResult{}, errors.New(
				"port observer process did not complete cleanly",
			)
		}
	case <-ctx.Done():
		s.abort()
		return peerPortResult{}, errors.New(
			"port observer process completion timed out",
		)
	}
	return result, nil
}

func (s *peerPortSession) abort() {
	if s == nil {
		return
	}
	done := s.abortDone
	s.abortOnce.Do(func() {
		if s.stdin != nil {
			_ = s.stdin.Close()
		}
		if s.cancel != nil {
			s.cancel()
		}
		timer := time.NewTimer(peerPortControlTimeout)
		defer timer.Stop()
		select {
		case <-s.wait:
		case <-timer.C:
		}
		if done != nil {
			close(done)
		}
	})
	if done != nil {
		<-done
	}
}

func (r *Runner) removePeerPortContainer(
	ctx context.Context,
	peerID string,
) error {
	if !fullContainerIDPattern.MatchString(peerID) {
		return errors.New("port observer removal identity is invalid")
	}
	stdout := &cappedBuffer{limit: peerPortControlLimit}
	stderr := &cappedBuffer{limit: peerPortControlLimit}
	exitCode, runErr := r.executor.Run(
		ctx,
		"docker",
		[]string{"rm", "--force", peerID},
		stdout,
		stderr,
	)
	if runErr != nil || exitCode != 0 ||
		stdout.truncated || stderr.truncated ||
		len(stderr.Bytes()) != 0 ||
		string(stdout.Bytes()) != peerID+"\n" {
		return errors.New(
			"port observer forced removal could not be confirmed",
		)
	}
	return nil
}

func summarizePeerPortObservation(
	state peerPortObservationState,
	completedAt time.Time,
) (domain.ObservationEvent, string, *domain.Error) {
	coverage := coverageUnavailable
	result := "unavailable"
	confidence := "unknown"
	identityVerified := state.startIdentityVerified &&
		state.readyIdentityVerified &&
		state.finalIdentityVerified
	comparison := comparePeerPortDeclarations(state)
	if comparison.Result != peerPortComparisonUntested {
		coverage = coverageBestEffort
		result = "observed"
		confidence = "high"
	}
	timestamp := state.observedAt
	if timestamp.IsZero() {
		timestamp = completedAt
	}
	details := map[string]any{
		"observerPlacement":          "peer-container-shared-network-namespace",
		"sharesTargetPIDNamespace":   false,
		"sharesTargetMountNamespace": false,
		"sharesTargetIPCNamespace":   false,
		"sharesTargetCgroup":         false,
		"processAttribution":         coverageUnavailable,
		"lifetimeSemantics":          "sample-window-only",
		"kernelEventCoverage":        coverageUnavailable,
		"shortLivedListenerGap":      true,
		"udpUnavailable":             true,
		"publicEvidence":             "aggregate-only",
		"evidenceBasis":              "aggregate-only",
		"comparisonResult":           comparison.Result,
		"sampleLimit":                peerPortSampleLimit,
		"intervalMillis":             peerPortIntervalMillis,
		"maxAllowedGapMillis":        peerPortMaxGapMillis,
		"identityVerified":           identityVerified,
		"namespaceIsolationVerified": state.namespaceIsolationVerified,
		"workloadQuiescenceVerified": state.workloadQuiescenceVerified,
		"peerRemoveVerified":         state.peerRemoveVerified,
		"canonicalDigestSemantics":   "helper-commitment-not-controller-recomputed",
	}
	if coverage == coverageBestEffort {
		details["observerAdapter"] = state.result.Adapter
		details["declaredEndpointCount"] =
			comparison.DeclaredEndpointCount
		details["baselineEndpointCount"] =
			comparison.BaselineEndpointCount
		details["sampledEndpointCount"] =
			comparison.SampledEndpointCount
		details["undeclaredEndpointCount"] =
			comparison.UndeclaredEndpointCount
		details["sampleCount"] = state.result.SampleCount
		details["maxSampleGapMillis"] =
			state.result.MaxSampleGapMillis
		details["transitionCount"] = state.result.TransitionCount
		details["canonicalSampleDigest"] =
			state.result.CanonicalSampleDigest
	}
	if state.failure != "" {
		details["failure"] = state.failure
	}
	event := domain.ObservationEvent{
		SchemaVersion: "1",
		Timestamp:     timestamp.UTC(),
		Phase:         domain.PhaseCleanup,
		Actor:         "trusted-runner",
		Operation:     "port.listener-trace.summary",
		Resource:      "tcp-listeners",
		Result:        result,
		Observer:      "docker-peer-port-listener-trace",
		Coverage:      coverage,
		Confidence:    confidence,
		Details:       details,
	}
	return event, coverage, peerPortDeclarationFinding(comparison)
}
