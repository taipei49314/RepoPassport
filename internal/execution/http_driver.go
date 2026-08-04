package execution

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/repopass/repopass/internal/domain"
)

const (
	nodeHTTPHelperScript   = `const http=require("node:http");let input="";process.stdin.setEncoding("utf8");process.stdin.on("data",chunk=>input+=chunk);process.stdin.on("end",()=>{let spec;try{spec=JSON.parse(input);}catch(_){process.stdout.write(JSON.stringify({ok:false,error:"invalid-spec"})+"\n");return;}const methods=new Set(["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"]);let target,authority;try{target=new URL(spec.url);authority=/^http:\/\/127\.0\.0\.1:([0-9]{1,5})(?:[/?]|$)/.exec(spec.url);}catch(_){process.stdout.write(JSON.stringify({ok:false,error:"invalid-spec"})+"\n");return;}if(!methods.has(spec.method)||target.protocol!=="http:"||target.hostname!=="127.0.0.1"||!Number.isSafeInteger(spec.port)||spec.port<1||spec.port>65535||!authority||authority[1]!==String(spec.port)||target.username||target.password||target.hash){process.stdout.write(JSON.stringify({ok:false,error:"invalid-spec"})+"\n");return;}let body;try{body=Buffer.from(spec.bodyBase64||"","base64");}catch(_){process.stdout.write(JSON.stringify({ok:false,error:"invalid-spec"})+"\n");return;}const headers=Object.create(null);for(const item of spec.headers||[]){if(!item||typeof item.name!=="string"||typeof item.value!=="string"||/[\r\n\0]/.test(item.name+item.value)){process.stdout.write(JSON.stringify({ok:false,error:"invalid-spec"})+"\n");return;}headers[item.name]=item.value;}const started=Date.now();let settled=false,request;const finish=value=>{if(settled)return;settled=true;clearTimeout(wallTimer);process.stdout.write(JSON.stringify(value)+"\n");};const wallTimer=setTimeout(()=>{if(request)request.destroy(new Error("timeout"));finish({ok:false,error:"timeout"});},spec.timeoutMillis);request=http.request({protocol:"http:",hostname:"127.0.0.1",port:spec.port,method:spec.method,path:target.pathname+target.search,headers,maxHeaderSize:spec.maxHeaderBytes},response=>{if(!Number.isSafeInteger(response.statusCode)||response.statusCode<200||response.statusCode>599){response.destroy();finish({ok:false,error:"transport"});return;}const raw=[];let headerBytes=0;for(let i=0;i<response.rawHeaders.length;i+=2){const name=String(response.rawHeaders[i]).toLowerCase(),value=String(response.rawHeaders[i+1]||"");headerBytes+=Buffer.byteLength(name)+Buffer.byteLength(value)+4;raw.push({name,value});}if(headerBytes>spec.maxHeaderBytes){response.destroy();finish({ok:false,error:"header-limit"});return;}const chunks=[];let stored=0,total=0,truncated=false;response.on("data",chunk=>{total+=chunk.length;if(stored<spec.maxResponseBytes){const take=Math.min(chunk.length,spec.maxResponseBytes-stored);if(take>0){chunks.push(chunk.subarray(0,take));stored+=take;}}if(total>spec.maxResponseBytes){truncated=true;response.destroy();}});response.on("end",()=>finish({ok:true,status:response.statusCode,headers:raw,bodyBase64:Buffer.concat(chunks).toString("base64"),bodyBytes:total,bodyTruncated:truncated,durationMillis:Date.now()-started}));response.on("close",()=>{if(truncated)finish({ok:true,status:response.statusCode,headers:raw,bodyBase64:Buffer.concat(chunks).toString("base64"),bodyBytes:total,bodyTruncated:true,durationMillis:Date.now()-started});});});request.setTimeout(spec.timeoutMillis,()=>{request.destroy(new Error("timeout"));});request.on("error",error=>finish({ok:false,error:error&&error.message==="timeout"?"timeout":"transport"}));if(body.length)request.write(body);request.end();});`
	pythonHTTPHelperScript = `import base64,http.client,json,signal,sys,time,urllib.parse
def emit(value):
    sys.stdout.write(json.dumps(value,separators=(",",":"))+"\n")
    sys.stdout.flush()
try:
    spec=json.load(sys.stdin)
    target=urllib.parse.urlsplit(spec["url"])
    port=spec["port"]
    if spec["method"] not in {"GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"} or target.scheme!="http" or target.hostname!="127.0.0.1" or type(port) is not int or port<1 or port>65535 or target.port!=port or target.netloc!="127.0.0.1:"+str(port) or target.username is not None or target.password is not None or target.fragment:
        raise ValueError()
    body=base64.b64decode(spec.get("bodyBase64",""),validate=True)
    headers={}
    for item in spec.get("headers",[]):
        name=item["name"]
        value=item["value"]
        if not isinstance(name,str) or not isinstance(value,str) or any(c in name+value for c in "\r\n\0"):
            raise ValueError()
        headers[name]=value
except Exception:
    emit({"ok":False,"error":"invalid-spec"})
    raise SystemExit(0)
started=time.monotonic()
class WallDeadline(Exception):
    pass
def wall_deadline(_signum,_frame):
    raise WallDeadline()
previous_handler=signal.signal(signal.SIGALRM,wall_deadline)
signal.setitimer(signal.ITIMER_REAL,spec["timeoutMillis"]/1000)
connection=None
try:
    connection=http.client.HTTPConnection("127.0.0.1",port,timeout=spec["timeoutMillis"]/1000)
    path=target.path or "/"
    if target.query:
        path+="?"+target.query
    connection.request(spec["method"],path,body=body if body else None,headers=headers)
    response=connection.getresponse()
    if response.status<200 or response.status>599:
        emit({"ok":False,"error":"transport"})
        raise SystemExit(0)
    response_headers=[]
    header_bytes=0
    for name,value in response.getheaders():
        name=name.lower()
        header_bytes+=len(name.encode("utf-8"))+len(value.encode("utf-8"))+4
        response_headers.append({"name":name,"value":value})
    if header_bytes>spec["maxHeaderBytes"]:
        emit({"ok":False,"error":"header-limit"})
    else:
        limit=spec["maxResponseBytes"]
        data=response.read(limit+1)
        truncated=len(data)>limit
        stored=data[:limit]
        emit({"ok":True,"status":response.status,"headers":response_headers,"bodyBase64":base64.b64encode(stored).decode("ascii"),"bodyBytes":len(data),"bodyTruncated":truncated,"durationMillis":int((time.monotonic()-started)*1000)})
except (TimeoutError,WallDeadline):
    emit({"ok":False,"error":"timeout"})
except Exception:
    emit({"ok":False,"error":"transport"})
finally:
    signal.setitimer(signal.ITIMER_REAL,0)
    signal.signal(signal.SIGALRM,previous_handler)
    if connection is not None:
        connection.close()`
)

var errTrustedHTTPTimeout = errors.New(
	"trusted HTTP helper exceeded its absolute deadline",
)

type httpHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type trustedHTTPRequest struct {
	ID      string
	Method  string
	URL     string
	Headers []httpHeader
	Body    []byte
	Timeout time.Duration
}

type httpHelperRequest struct {
	Method           string       `json:"method"`
	URL              string       `json:"url"`
	Port             int          `json:"port"`
	Headers          []httpHeader `json:"headers"`
	BodyBase64       string       `json:"bodyBase64"`
	TimeoutMillis    int64        `json:"timeoutMillis"`
	MaxResponseBytes int64        `json:"maxResponseBytes"`
	MaxHeaderBytes   int64        `json:"maxHeaderBytes"`
}

type httpHelperResponse struct {
	OK             bool         `json:"ok"`
	Error          string       `json:"error,omitempty"`
	Status         int          `json:"status,omitempty"`
	Headers        []httpHeader `json:"headers,omitempty"`
	BodyBase64     string       `json:"bodyBase64,omitempty"`
	BodyBytes      int64        `json:"bodyBytes,omitempty"`
	BodyTruncated  bool         `json:"bodyTruncated,omitempty"`
	DurationMillis int64        `json:"durationMillis,omitempty"`
}

func decodeHTTPHelperResponse(raw []byte) (httpHelperResponse, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return httpHelperResponse{}, errors.New(
			"trusted HTTP helper control must be one JSON object",
		)
	}

	var response httpHelperResponse
	seen := make(map[string]struct{}, 8)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return httpHelperResponse{}, errors.New(
				"trusted HTTP helper control contains an invalid object key",
			)
		}
		key, ok := token.(string)
		if !ok {
			return httpHelperResponse{}, errors.New(
				"trusted HTTP helper control contains a non-string object key",
			)
		}
		if _, duplicate := seen[key]; duplicate {
			return httpHelperResponse{}, errors.New(
				"trusted HTTP helper control contains a duplicate object key",
			)
		}
		seen[key] = struct{}{}

		switch key {
		case "ok":
			var value *bool
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpHelperResponse{}, errors.New(
					"trusted HTTP helper control ok field is invalid",
				)
			}
			response.OK = *value
		case "error":
			var value *string
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpHelperResponse{}, errors.New(
					"trusted HTTP helper control error field is invalid",
				)
			}
			response.Error = *value
		case "status":
			var value *int
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpHelperResponse{}, errors.New(
					"trusted HTTP helper control status field is invalid",
				)
			}
			response.Status = *value
		case "headers":
			response.Headers, err = decodeHTTPHelperHeaders(decoder)
			if err != nil {
				return httpHelperResponse{}, err
			}
		case "bodyBase64":
			var value *string
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpHelperResponse{}, errors.New(
					"trusted HTTP helper control body field is invalid",
				)
			}
			response.BodyBase64 = *value
		case "bodyBytes":
			var value *int64
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpHelperResponse{}, errors.New(
					"trusted HTTP helper control body size field is invalid",
				)
			}
			response.BodyBytes = *value
		case "bodyTruncated":
			var value *bool
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpHelperResponse{}, errors.New(
					"trusted HTTP helper control truncation field is invalid",
				)
			}
			response.BodyTruncated = *value
		case "durationMillis":
			var value *int64
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpHelperResponse{}, errors.New(
					"trusted HTTP helper control duration field is invalid",
				)
			}
			response.DurationMillis = *value
		default:
			return httpHelperResponse{}, errors.New(
				"trusted HTTP helper control contains an unknown object key",
			)
		}
	}

	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return httpHelperResponse{}, errors.New(
			"trusted HTTP helper control object is not closed",
		)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return httpHelperResponse{}, errors.New(
			"trusted HTTP helper control must contain exactly one JSON object",
		)
	}
	if _, present := seen["ok"]; !present {
		return httpHelperResponse{}, errors.New(
			"trusted HTTP helper control is missing ok",
		)
	}
	if response.OK {
		required := [...]string{
			"ok",
			"status",
			"headers",
			"bodyBase64",
			"bodyBytes",
			"bodyTruncated",
			"durationMillis",
		}
		if len(seen) != len(required) ||
			!containsEveryHTTPHelperField(seen, required[:]) {
			return httpHelperResponse{}, errors.New(
				"trusted HTTP helper returned an invalid success envelope",
			)
		}
		return response, nil
	}
	required := [...]string{"ok", "error"}
	if len(seen) != len(required) ||
		!containsEveryHTTPHelperField(seen, required[:]) {
		return httpHelperResponse{}, errors.New(
			"trusted HTTP helper returned an invalid failure envelope",
		)
	}
	return response, nil
}

func containsEveryHTTPHelperField(
	seen map[string]struct{},
	required []string,
) bool {
	for _, field := range required {
		if _, present := seen[field]; !present {
			return false
		}
	}
	return true
}

func decodeHTTPHelperHeaders(
	decoder *json.Decoder,
) ([]httpHeader, error) {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return nil, errors.New(
			"trusted HTTP helper control headers field is invalid",
		)
	}
	headers := make([]httpHeader, 0)
	for decoder.More() {
		if len(headers) >= domain.AlphaHTTPMaxHeaders {
			return nil, errors.New(
				"trusted HTTP helper returned too many headers",
			)
		}
		header, err := decodeHTTPHelperHeader(decoder)
		if err != nil {
			return nil, err
		}
		headers = append(headers, header)
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim(']') {
		return nil, errors.New(
			"trusted HTTP helper control headers array is not closed",
		)
	}
	return headers, nil
}

func decodeHTTPHelperHeader(
	decoder *json.Decoder,
) (httpHeader, error) {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return httpHeader{}, errors.New(
			"trusted HTTP helper control header must be an object",
		)
	}
	var header httpHeader
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return httpHeader{}, errors.New(
				"trusted HTTP helper control header has an invalid object key",
			)
		}
		key, ok := token.(string)
		if !ok {
			return httpHeader{}, errors.New(
				"trusted HTTP helper control header has a non-string object key",
			)
		}
		if _, duplicate := seen[key]; duplicate {
			return httpHeader{}, errors.New(
				"trusted HTTP helper control header has a duplicate object key",
			)
		}
		seen[key] = struct{}{}
		var value *string
		switch key {
		case "name":
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpHeader{}, errors.New(
					"trusted HTTP helper control header name is invalid",
				)
			}
			header.Name = *value
		case "value":
			if err := decoder.Decode(&value); err != nil || value == nil {
				return httpHeader{}, errors.New(
					"trusted HTTP helper control header value is invalid",
				)
			}
			header.Value = *value
		default:
			return httpHeader{}, errors.New(
				"trusted HTTP helper control header has an unknown object key",
			)
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') {
		return httpHeader{}, errors.New(
			"trusted HTTP helper control header object is not closed",
		)
	}
	if len(seen) != 2 {
		return httpHeader{}, errors.New(
			"trusted HTTP helper control header is missing a field",
		)
	}
	return header, nil
}

type trustedHTTPResponse struct {
	Status         int
	Headers        []httpHeader
	Body           []byte
	BodyBytes      int64
	BodyTruncated  bool
	DurationMillis int64
}

func trustedHTTPRequestFromPlan(
	request domain.PlanHTTPRequest,
	defaultTimeout time.Duration,
	maxBodyBytes int64,
	maxHeaderBytes int64,
) (trustedHTTPRequest, error) {
	timeout := defaultTimeout
	if request.Timeout != "" {
		parsed, err := domain.ParseAlphaHTTPDuration(
			request.Timeout,
			domain.AlphaHTTPMaxRequestTime,
		)
		if err != nil {
			return trustedHTTPRequest{}, errors.New("invalid HTTP request timeout")
		}
		timeout = parsed
	}
	if !isWholeMillisecondDuration(timeout) ||
		timeout > domain.AlphaHTTPMaxRequestTime {
		return trustedHTTPRequest{}, errors.New("invalid HTTP request timeout")
	}
	if request.Method !=
		strings.ToLower(strings.TrimSpace(request.Method)) {
		return trustedHTTPRequest{}, errors.New("HTTP request method is not canonical")
	}
	if err := domain.ValidateAlphaHTTPHeaders(
		request.Headers,
		request.JSON != nil,
	); err != nil {
		return trustedHTTPRequest{}, err
	}
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	headers := make([]httpHeader, 0, len(request.Headers)+1)
	seenHeaders := make(map[string]struct{}, len(request.Headers))
	totalHeaderBytes := int64(0)
	for name, value := range request.Headers {
		canonicalName := strings.ToLower(strings.TrimSpace(name))
		if name != canonicalName {
			return trustedHTTPRequest{}, errors.New("HTTP request header name is not canonical")
		}
		if !validHTTPHeaderName(canonicalName) ||
			!isPrintableASCII(value) {
			return trustedHTTPRequest{}, errors.New("invalid HTTP request header")
		}
		if len([]byte(value)) > domain.AlphaHTTPMaxHeaderValueBytes {
			return trustedHTTPRequest{}, errors.New("oversized HTTP request header")
		}
		if _, exists := seenHeaders[canonicalName]; exists {
			return trustedHTTPRequest{}, errors.New("duplicate HTTP request header")
		}
		switch canonicalName {
		case "authorization", "proxy-authorization", "cookie",
			"x-api-key", "host", "content-length", "transfer-encoding",
			"connection":
			return trustedHTTPRequest{}, errors.New("forbidden HTTP request header")
		}
		seenHeaders[canonicalName] = struct{}{}
		headers = append(headers, httpHeader{Name: canonicalName, Value: value})
		totalHeaderBytes += int64(
			len([]byte(canonicalName)) + len([]byte(value)) + 4,
		)
	}
	var body []byte
	switch {
	case request.Body != nil && request.JSON != nil:
		return trustedHTTPRequest{}, errors.New("HTTP request has both text and JSON bodies")
	case request.Body != nil:
		body = []byte(*request.Body)
	case request.JSON != nil:
		if !json.Valid(request.JSON) {
			return trustedHTTPRequest{}, errors.New("HTTP request JSON is invalid")
		}
		body = bytes.Clone(request.JSON)
		if _, exists := seenHeaders[domain.AlphaHTTPContentTypeName]; !exists {
			headers = append(headers, httpHeader{
				Name:  domain.AlphaHTTPContentTypeName,
				Value: domain.AlphaHTTPJSONContentType,
			})
			seenHeaders[domain.AlphaHTTPContentTypeName] = struct{}{}
			totalHeaderBytes += int64(
				len(domain.AlphaHTTPContentTypeName) +
					len(domain.AlphaHTTPJSONContentType) + 4,
			)
		}
	}
	effectiveHeaderLimit := maxHeaderBytes
	if effectiveHeaderLimit <= 0 ||
		effectiveHeaderLimit > domain.AlphaHTTPMaxHeaderAggregateBytes {
		effectiveHeaderLimit =
			domain.AlphaHTTPMaxHeaderAggregateBytes
	}
	if len(headers) > domain.AlphaHTTPMaxHeaders {
		return trustedHTTPRequest{}, errors.New("too many HTTP request headers")
	}
	if totalHeaderBytes > effectiveHeaderLimit {
		return trustedHTTPRequest{}, errors.New("HTTP request headers exceed runner limit")
	}
	effectiveBodyLimit := maxBodyBytes
	if effectiveBodyLimit <= 0 ||
		effectiveBodyLimit > domain.AlphaHTTPMaxRequestBodyBytes {
		effectiveBodyLimit =
			domain.AlphaHTTPMaxRequestBodyBytes
	}
	if int64(len(body)) > effectiveBodyLimit {
		return trustedHTTPRequest{}, errors.New("HTTP request body exceeds runner limit")
	}
	sort.Slice(headers, func(i, j int) bool {
		return headers[i].Name < headers[j].Name
	})
	if err := validateLoopbackHTTPURL(request.URL); err != nil {
		return trustedHTTPRequest{}, err
	}
	if !allowedHTTPMethod(method) {
		return trustedHTTPRequest{}, errors.New("HTTP request method is unsupported")
	}
	return trustedHTTPRequest{
		ID: request.ID, Method: method, URL: request.URL,
		Headers: headers, Body: body, Timeout: timeout,
	}, nil
}

func (r *Runner) runTrustedHTTPRequest(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	request trustedHTTPRequest,
) (
	trustedHTTPResponse,
	error,
) {
	return r.runTrustedHTTPRequestWithStart(
		ctx,
		prepared,
		containerName,
		request,
		nil,
	)
}

func (r *Runner) runTrustedHTTPRequestWithStart(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	request trustedHTTPRequest,
	onStart func(),
) (
	responseResult trustedHTTPResponse,
	returnErr error,
) {
	residueUncertain := false
	defer func() {
		if residueUncertain && returnErr != nil {
			returnErr = r.cleanupHTTPDriverAfterFailure(
				prepared,
				containerName,
				returnErr,
			)
		}
	}()
	inputExecutor, ok := r.executor.(InputCommandExecutor)
	if !ok {
		return trustedHTTPResponse{}, domain.NewError(
			domain.CodeRunnerFeatureUnavailable,
			domain.SeverityHigh,
			"Runner command executor cannot provide bounded stdin to the trusted HTTP helper.",
		)
	}
	if err := r.validateTrustedHTTPRequest(request); err != nil {
		return trustedHTTPResponse{}, err
	}
	if ctx.Err() != nil {
		return trustedHTTPResponse{}, ctx.Err()
	}
	if request.Timeout > r.config.MaxStepTimeout {
		return trustedHTTPResponse{}, errors.New("HTTP request timeout exceeds runner limit")
	}
	timeoutMillis := request.Timeout.Milliseconds()
	_, port, _ := domain.ParseAlphaHTTPURL(request.URL)
	maxHeaderBytes := r.config.MaxHTTPHeaderBytes
	if maxHeaderBytes <= 0 ||
		maxHeaderBytes > domain.AlphaHTTPMaxHeaderAggregateBytes {
		maxHeaderBytes = domain.AlphaHTTPMaxHeaderAggregateBytes
	}
	spec := httpHelperRequest{
		Method: request.Method, URL: request.URL, Port: port,
		Headers:          request.Headers,
		BodyBase64:       base64.StdEncoding.EncodeToString(request.Body),
		TimeoutMillis:    timeoutMillis,
		MaxResponseBytes: r.config.MaxHTTPResponseBytes,
		MaxHeaderBytes:   maxHeaderBytes,
	}
	input, err := json.Marshal(spec)
	if err != nil {
		return trustedHTTPResponse{}, err
	}
	executable, ok := runtimeExecutable(prepared.executionPlan.RuntimeAdapter)
	if !ok {
		return trustedHTTPResponse{}, errors.New("runtime adapter has no trusted HTTP helper")
	}
	script := nodeHTTPHelperScript
	scriptArgs := []string{"-e", script}
	if prepared.executionPlan.RuntimeAdapter == "python" {
		script = pythonHTTPHelperScript
		scriptArgs = []string{"-I", "-S", "-c", script}
	}
	args := []string{
		"exec", "-i",
		"--user", containerDriverUser,
		"--workdir", trustedHelperWorkdir,
		containerName,
		executable,
	}
	args = append(args, scriptArgs...)
	stdout := &cappedBuffer{limit: r.config.MaxHTTPControlBytes}
	stderr := &cappedBuffer{limit: r.config.DoctorOutputBytes}
	residueUncertain = true
	if onStart != nil {
		onStart()
	}
	exitCode, runErr := inputExecutor.RunInput(
		ctx,
		prepared.Backend,
		args,
		bytes.NewReader(input),
		stdout,
		stderr,
	)
	if runErr == nil && exitCode == 0 {
		residueUncertain = false
	}
	if runErr != nil || exitCode != 0 {
		return trustedHTTPResponse{}, fmt.Errorf(
			"trusted HTTP helper failed with exit %d: %w",
			exitCode,
			runErr,
		)
	}
	if stdout.truncated {
		return trustedHTTPResponse{}, errors.New("trusted HTTP helper control response exceeded its limit")
	}
	response, err := decodeHTTPHelperResponse(stdout.Bytes())
	if err != nil {
		return trustedHTTPResponse{}, err
	}
	if !response.OK {
		switch response.Error {
		case "timeout":
			return trustedHTTPResponse{}, errTrustedHTTPTimeout
		case "transport", "header-limit", "invalid-spec":
			return trustedHTTPResponse{}, fmt.Errorf(
				"trusted HTTP helper reported %s",
				response.Error,
			)
		default:
			return trustedHTTPResponse{}, errors.New("trusted HTTP helper returned an unknown failure")
		}
	}
	if response.Status < domain.AlphaHTTPMinimumStatus ||
		response.Status > domain.AlphaHTTPMaximumStatus ||
		response.DurationMillis < 0 ||
		response.DurationMillis >
			(request.Timeout+250*time.Millisecond).Milliseconds() ||
		response.BodyBytes < 0 {
		return trustedHTTPResponse{}, errors.New("trusted HTTP helper returned invalid metadata")
	}
	body, err := base64.StdEncoding.DecodeString(response.BodyBase64)
	if err != nil ||
		base64.StdEncoding.EncodeToString(body) != response.BodyBase64 ||
		int64(len(body)) > r.config.MaxHTTPResponseBytes ||
		(!response.BodyTruncated && response.BodyBytes != int64(len(body))) ||
		(response.BodyTruncated && response.BodyBytes <= int64(len(body))) {
		return trustedHTTPResponse{}, errors.New("trusted HTTP helper returned an invalid bounded body")
	}
	totalHeaderBytes := int64(0)
	for index := range response.Headers {
		canonicalName := strings.ToLower(
			strings.TrimSpace(response.Headers[index].Name),
		)
		if response.Headers[index].Name != canonicalName ||
			!validHTTPHeaderName(response.Headers[index].Name) ||
			len([]byte(response.Headers[index].Value)) >
				domain.AlphaHTTPMaxHeaderValueBytes ||
			strings.ContainsAny(response.Headers[index].Value, "\r\n\x00") {
			return trustedHTTPResponse{}, errors.New("trusted HTTP helper returned an invalid header")
		}
		totalHeaderBytes += int64(
			len(response.Headers[index].Name) +
				len(response.Headers[index].Value) + 4,
		)
	}
	if totalHeaderBytes > maxHeaderBytes {
		return trustedHTTPResponse{}, errors.New("trusted HTTP helper returned oversized headers")
	}
	return trustedHTTPResponse{
		Status: response.Status, Headers: response.Headers, Body: body,
		BodyBytes: response.BodyBytes, BodyTruncated: response.BodyTruncated,
		DurationMillis: response.DurationMillis,
	}, nil
}

func validateLoopbackHTTPURL(value string) error {
	_, _, err := domain.ParseAlphaHTTPURL(value)
	return err
}

func (r *Runner) validateTrustedHTTPRequest(
	request trustedHTTPRequest,
) error {
	if !assertionIDPattern.MatchString(request.ID) {
		return errors.New("trusted HTTP request ID is invalid")
	}
	if !allowedHTTPMethod(request.Method) {
		return errors.New("trusted HTTP request method is invalid")
	}
	if err := validateLoopbackHTTPURL(request.URL); err != nil {
		return err
	}
	if !isWholeMillisecondDuration(request.Timeout) {
		return errors.New("trusted HTTP request timeout is invalid")
	}
	if request.Timeout > domain.AlphaHTTPMaxRequestTime {
		return errors.New("trusted HTTP request timeout exceeds the alpha limit")
	}
	if len(request.Headers) > domain.AlphaHTTPMaxHeaders {
		return errors.New("trusted HTTP request has too many headers")
	}
	seen := make(map[string]struct{}, len(request.Headers))
	totalHeaderBytes := int64(0)
	for _, header := range request.Headers {
		if header.Name != strings.ToLower(strings.TrimSpace(header.Name)) ||
			!validHTTPHeaderName(header.Name) ||
			!isPrintableASCII(header.Value) ||
			len([]byte(header.Value)) >
				domain.AlphaHTTPMaxHeaderValueBytes {
			return errors.New("trusted HTTP request header is invalid")
		}
		if _, exists := seen[header.Name]; exists {
			return errors.New("trusted HTTP request header is duplicated")
		}
		switch header.Name {
		case "authorization", "proxy-authorization", "cookie",
			"x-api-key", "host", "content-length", "transfer-encoding",
			"connection":
			return errors.New("trusted HTTP request header is forbidden")
		}
		seen[header.Name] = struct{}{}
		totalHeaderBytes += int64(
			len([]byte(header.Name)) +
				len([]byte(header.Value)) + 4,
		)
	}
	headerLimit := r.config.MaxHTTPHeaderBytes
	if headerLimit <= 0 ||
		headerLimit > domain.AlphaHTTPMaxHeaderAggregateBytes {
		headerLimit = domain.AlphaHTTPMaxHeaderAggregateBytes
	}
	if totalHeaderBytes > headerLimit {
		return errors.New("trusted HTTP request headers exceed runner limit")
	}
	bodyLimit := r.config.MaxHTTPRequestBytes
	if bodyLimit <= 0 ||
		bodyLimit > domain.AlphaHTTPMaxRequestBodyBytes {
		bodyLimit = domain.AlphaHTTPMaxRequestBodyBytes
	}
	if int64(len(request.Body)) > bodyLimit {
		return errors.New("trusted HTTP request body exceeds runner limit")
	}
	return nil
}

func isWholeMillisecondDuration(value time.Duration) bool {
	return value >= domain.AlphaHTTPMinimumDuration &&
		value%time.Millisecond == 0
}

func isPrintableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func sameHTTPOrigin(first, second string) bool {
	left, leftErr := url.Parse(first)
	right, rightErr := url.Parse(second)
	return leftErr == nil && rightErr == nil &&
		left.Scheme == right.Scheme &&
		left.Host == right.Host
}

func sanitizedHTTPResource(value string) (string, bool) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "invalid-http-resource", false
	}
	resource := parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath()
	return resource, parsed.RawQuery != ""
}

func allowedHTTPMethod(value string) bool {
	switch value {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return true
	default:
		return false
	}
}

func validHTTPHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return false
	}
	return true
}

func (r *Runner) executeHTTPJourney(
	ctx context.Context,
	prepared *PreparedRun,
	containerName string,
	service *runningService,
) (
	map[string]httpExchange,
	map[string]domain.AssertionResult,
	[]domain.ObservationEvent,
	bool,
	*domain.Error,
) {
	exchanges := make(map[string]httpExchange)
	assertionResults := make(map[string]domain.AssertionResult)
	var observations []domain.ObservationEvent
	driverStarted := false
	if prepared == nil || !prepared.executionPlanSealed ||
		prepared.executionPlan.HTTPJourney == nil {
		return exchanges, assertionResults, observations, driverStarted, domain.NewError(
			domain.CodePlanUnresolved,
			domain.SeverityCritical,
			"Prepared HTTP journey has no sealed execution-plan snapshot.",
		)
	}
	assertions := make(
		map[string]domain.PlanAssertion,
		len(prepared.executionPlan.JourneyAssertions),
	)
	for _, assertion := range prepared.executionPlan.JourneyAssertions {
		assertions[assertion.ID] = assertion
	}
	for _, step := range prepared.executionPlan.HTTPJourney.Steps {
		if ctx.Err() != nil {
			return exchanges, assertionResults, observations, driverStarted,
				httpJourneyContextError(ctx.Err())
		}
		if serviceResult, exited := pollServiceResult(service); exited {
			if serviceResult.primaryError != nil {
				return exchanges, assertionResults, observations, driverStarted, serviceResult.primaryError
			}
			err := domain.NewError(
				domain.CodeServiceStartFailed,
				domain.SeverityHigh,
				"HTTP service exited before its journey completed.",
			)
			err.Phase = domain.PhaseExercise
			err.Details = map[string]any{
				"service":  service.command.ID,
				"exitCode": serviceResult.result.ExitCode,
			}
			return exchanges, assertionResults, observations, driverStarted, err
		}
		if step.Request != nil {
			request, err := trustedHTTPRequestFromPlan(
				*step.Request,
				10*time.Second,
				r.config.MaxHTTPRequestBytes,
				r.config.MaxHTTPHeaderBytes,
			)
			if err != nil {
				finding := domain.WrapError(
					domain.CodePlanUnresolved,
					domain.SeverityHigh,
					"Resolved HTTP request failed runner revalidation.",
					err,
				)
				finding.Phase = domain.PhaseExercise
				return exchanges, assertionResults, observations, driverStarted, finding
			}
			requestCtx, cancel := context.WithTimeout(
				ctx,
				request.Timeout+250*time.Millisecond,
			)
			response, requestErr := r.runTrustedHTTPRequestWithStart(
				requestCtx,
				prepared,
				containerName,
				request,
				func() { driverStarted = true },
			)
			contextErr := requestCtx.Err()
			cancel()
			if requestErr == nil && contextErr != nil {
				requestErr = contextErr
			}
			result := "succeeded"
			resource, queryPresent := sanitizedHTTPResource(request.URL)
			details := map[string]any{
				"requestId":    request.ID,
				"method":       request.Method,
				"queryPresent": queryPresent,
			}
			if requestErr != nil {
				result = "failed"
				details["failure"] = "transport-or-helper"
			} else {
				details["status"] = response.Status
				details["responseBytes"] = response.BodyBytes
				details["bodyTruncated"] = response.BodyTruncated
				details["durationMillis"] = response.DurationMillis
				exchanges[request.ID] = httpExchange{
					Request: request, Response: response,
				}
			}
			observations = append(observations, domain.ObservationEvent{
				SchemaVersion: "1",
				Timestamp:     r.now().UTC(),
				Phase:         domain.PhaseExercise,
				Actor:         "trusted-http-driver",
				Operation:     "http.request",
				Resource:      resource,
				Result:        result,
				Observer:      prepared.Backend + "-exec-http-helper",
				Coverage:      coverageFull,
				Confidence:    "high",
				Details:       details,
			})
			if requestErr != nil {
				code := domain.CodeJourneyAssertionFailed
				severity := domain.SeverityHigh
				message := "Trusted HTTP journey request could not be completed."
				if errors.Is(requestErr, errHTTPDriverResidue) {
					code = domain.CodeProcessLeak
					message = "Trusted HTTP driver residue could not be excluded."
				} else if errors.Is(ctx.Err(), context.Canceled) ||
					errors.Is(contextErr, context.Canceled) ||
					errors.Is(requestErr, context.Canceled) {
					code = domain.CodeCancelled
					severity = domain.SeverityWarning
					message = "Trusted HTTP journey request was cancelled."
				} else if errors.Is(
					requestErr,
					errTrustedHTTPTimeout,
				) ||
					errors.Is(contextErr, context.DeadlineExceeded) ||
					errors.Is(requestErr, context.DeadlineExceeded) {
					code = domain.CodeTimeout
					message = "Trusted HTTP journey request exceeded its deadline."
				}
				finding := domain.WrapError(
					code,
					severity,
					message,
					requestErr,
				)
				finding.Phase = domain.PhaseExercise
				finding.EvidenceRefs = []string{
					"http-request:" + request.ID,
				}
				return exchanges, assertionResults, observations, driverStarted, finding
			}
			continue
		}

		assertion := assertions[step.AssertionID]
		if assertion.JSONFile != nil {
			result := r.inspectHTTPJSONFileAssertionWithStart(
				ctx,
				prepared,
				containerName,
				assertion,
				func() { driverStarted = true },
			)
			assertionResults[assertion.ID] = result
			if result.Status == "failed" {
				finding := domain.NewError(
					domain.CodeJourneyAssertionFailed,
					domain.SeverityHigh,
					"An ordered HTTP JSON file assertion failed.",
				)
				finding.Phase = domain.PhaseExercise
				finding.EvidenceRefs = cloneStrings(
					result.EvidenceRefs,
				)
				finding.Details = map[string]any{
					"assertionId": result.ID,
				}
				return exchanges, assertionResults, observations, driverStarted, finding
			}
			if result.Status != "passed" {
				finding := domain.NewError(
					domain.CodeObserverIncomplete,
					domain.SeverityHigh,
					"An ordered HTTP JSON file assertion is inconclusive.",
				)
				finding.Phase = domain.PhaseExercise
				finding.EvidenceRefs = cloneStrings(
					result.EvidenceRefs,
				)
				finding.Details = map[string]any{
					"assertionId": result.ID,
				}
				return exchanges, assertionResults, observations, driverStarted, finding
			}
			continue
		}
		if assertion.FileExists != "" {
			result := r.inspectHTTPFileAssertionWithStart(
				ctx,
				prepared,
				containerName,
				assertion,
				func() { driverStarted = true },
			)
			assertionResults[assertion.ID] = result
			if result.Status == "failed" {
				finding := domain.NewError(
					domain.CodeJourneyAssertionFailed,
					domain.SeverityHigh,
					"An ordered HTTP file assertion failed.",
				)
				finding.Phase = domain.PhaseExercise
				finding.EvidenceRefs = cloneStrings(
					result.EvidenceRefs,
				)
				finding.Details = map[string]any{
					"assertionId": result.ID,
				}
				return exchanges, assertionResults, observations, driverStarted, finding
			}
			if result.Status != "passed" {
				finding := domain.NewError(
					domain.CodeObserverIncomplete,
					domain.SeverityHigh,
					"An ordered HTTP file assertion is inconclusive.",
				)
				finding.Phase = domain.PhaseExercise
				finding.EvidenceRefs = cloneStrings(
					result.EvidenceRefs,
				)
				finding.Details = map[string]any{
					"assertionId": result.ID,
				}
				return exchanges, assertionResults, observations, driverStarted, finding
			}
			continue
		}
		if assertion.Response == nil {
			continue
		}
		result := evaluateHTTPResponseAssertion(
			prepared,
			assertion,
			exchanges,
		)
		assertionResults[assertion.ID] = result
		if result.Status == "failed" {
			finding := domain.NewError(
				domain.CodeJourneyAssertionFailed,
				domain.SeverityHigh,
				"One or more required HTTP response assertions failed.",
			)
			finding.Phase = domain.PhaseExercise
			finding.EvidenceRefs = cloneStrings(result.EvidenceRefs)
			finding.Details = map[string]any{
				"assertionId": result.ID,
			}
			return exchanges, assertionResults, observations, driverStarted, finding
		}
		if result.Status == "blocked" ||
			result.Status == "inconclusive" {
			finding := domain.NewError(
				domain.CodeObserverIncomplete,
				domain.SeverityHigh,
				"A required HTTP response assertion is inconclusive.",
			)
			finding.Phase = domain.PhaseExercise
			finding.EvidenceRefs = cloneStrings(result.EvidenceRefs)
			finding.Details = map[string]any{
				"assertionId": result.ID,
			}
			return exchanges, assertionResults, observations, driverStarted, finding
		}
	}
	if serviceResult, exited := pollServiceResult(service); exited {
		if serviceResult.primaryError != nil {
			return exchanges, assertionResults, observations, driverStarted, serviceResult.primaryError
		}
		err := domain.NewError(
			domain.CodeServiceStartFailed,
			domain.SeverityHigh,
			"HTTP service exited before its resolved cleanup signal.",
		)
		err.Phase = domain.PhaseExercise
		err.Details = map[string]any{
			"service":  service.command.ID,
			"exitCode": serviceResult.result.ExitCode,
		}
		return exchanges, assertionResults, observations, driverStarted, err
	}
	return exchanges, assertionResults, observations, driverStarted, nil
}

func httpJourneyContextError(cause error) *domain.Error {
	code := domain.CodeTimeout
	severity := domain.SeverityHigh
	message := "Trusted HTTP journey exceeded its run deadline."
	if errors.Is(cause, context.Canceled) {
		code = domain.CodeCancelled
		severity = domain.SeverityWarning
		message = "Trusted HTTP journey was cancelled."
	}
	err := domain.WrapError(code, severity, message, cause)
	err.Phase = domain.PhaseExercise
	return err
}
