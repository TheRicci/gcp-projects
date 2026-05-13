package main

import (
	"encoding/json"
	"time"
)

type SharedData struct {
	SuricataList []*Alert
	ModsecList   []*Alert
	WazuhList    []*Alert
	AlertsList   []*Alert
	IDSAlertsMap map[string]*Alert
	AlertsMap    map[string]*Alert
}

type Alert struct {
	IP             string
	DstPort        *int
	Url            *string
	Threat         *string
	Severity       *int
	FirstTimestamp *time.Time
	LastTimestamp  *time.Time
	Tier           *int
	LogType        *string
	Quantity       int
	Suricata       []SuricataEveLog
	Modsec         []ModsecAuditLog
	Wazuh          []WazuhLog
}

// ModsecAuditLog represents a full ModSecurity audit record in JSON form.
type ModsecAuditLog struct {
	Transaction struct {
		ClientIP   string `json:"client_ip"`
		TimeStamp  string `json:"time_stamp"`
		ServerID   string `json:"server_id"`
		ClientPort int    `json:"client_port"`
		HostIP     string `json:"host_ip"`
		HostPort   int    `json:"host_port"`
		UniqueID   string `json:"unique_id"`
		Request    struct {
			Method      string            `json:"method"`
			HTTPVersion float64           `json:"http_version"`
			URI         string            `json:"uri"`
			Headers     map[string]string `json:"headers"`
		} `json:"request"`
		Response struct {
			Body     string            `json:"body"`
			HTTPCode int               `json:"http_code"`
			Headers  map[string]string `json:"headers"`
		} `json:"response"`
		Producer struct {
			ModSecurity    string   `json:"modsecurity"`
			Connector      string   `json:"connector"`
			SecRulesEngine string   `json:"secrules_engine"`
			Components     []string `json:"components"`
		} `json:"producer"`
		Messages []struct {
			Message string `json:"message"`
			Details struct {
				Match      string   `json:"match"`
				Reference  string   `json:"reference"`
				RuleID     string   `json:"ruleId"`
				File       string   `json:"file"`
				LineNumber string   `json:"lineNumber"`
				Data       string   `json:"data"`
				Severity   string   `json:"severity"`
				Ver        string   `json:"ver"`
				Rev        string   `json:"rev"`
				Tags       []string `json:"tags"`
				Maturity   string   `json:"maturity"`
				Accuracy   string   `json:"accuracy"`
			} `json:"details"`
		} `json:"messages"`
	} `json:"transaction"`
}

// SuricataEveLog represents one line of Suricata’s EVE JSON.
type SuricataEveLog struct {
	Timestamp string `json:"timestamp"`
	FlowID    int64  `json:"flow_id"`
	InIface   string `json:"in_iface"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	SrcPort   int    `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Proto     string `json:"proto"`
	PktSrc    string `json:"pkt_src"`
	TxID      int    `json:"tx_id"`
	Alert     struct {
		Action      string `json:"action"`
		Gid         int    `json:"gid"`
		SignatureID int    `json:"signature_id"`
		Rev         int    `json:"rev"`
		Signature   string `json:"signature"`
		Category    string `json:"category"`
		Severity    int    `json:"severity"`
		Metadata    struct {
			AffectedProduct   []string `json:"affected_product"`
			AttackTarget      []string `json:"attack_target"`
			Confidence        []string `json:"confidence"`
			CreatedAt         []string `json:"created_at"`
			Deployment        []string `json:"deployment"`
			SignatureSeverity []string `json:"signature_severity"`
			Tag               []string `json:"tag"`
			UpdatedAt         []string `json:"updated_at"`
		} `json:"metadata"`
	} `json:"alert"`
	HTTP struct {
		Hostname        string `json:"hostname"`
		URL             string `json:"url"`
		HTTPUserAgent   string `json:"http_user_agent"`
		XFF             string `json:"xff"`
		HTTPContentType string `json:"http_content_type"`
		HTTPMethod      string `json:"http_method"`
		Protocol        string `json:"protocol"`
		Status          int    `json:"status"`
		Length          int    `json:"length"`
	} `json:"http"`
	AppProto  string `json:"app_proto"`
	Direction string `json:"direction"`
	Flow      struct {
		PktsToserver  int    `json:"pkts_toserver"`
		PktsToclient  int    `json:"pkts_toclient"`
		BytesToserver int    `json:"bytes_toserver"`
		BytesToclient int    `json:"bytes_toclient"`
		Start         string `json:"start"`
		SrcIP         string `json:"src_ip"`
		DestIP        string `json:"dest_ip"`
		SrcPort       int    `json:"src_port"`
		DestPort      int    `json:"dest_port"`
	} `json:"flow"`
}

type WazuhLog struct {
	// Common fields present in most Wazuh logs
	Timestamp string `json:"timestamp"`

	// Agent information
	Agent struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
		IP   string `json:"ip,omitempty"`
	} `json:"agent,omitempty"`

	// Manager information
	Manager struct {
		Name string `json:"name,omitempty"`
	} `json:"manager,omitempty"`

	// Rule information
	Rule struct {
		ID          int      `json:"id,omitempty"`
		Level       int      `json:"level,omitempty"`
		Description string   `json:"description,omitempty"`
		Groups      []string `json:"groups,omitempty"`
		MITRE       struct {
			ID        []string `json:"id,omitempty"`
			Tactic    []string `json:"tactic,omitempty"`
			Technique []string `json:"technique,omitempty"`
		} `json:"mitre,omitempty"`
		GDPR    []string `json:"gdpr,omitempty"`
		HIPAA   []string `json:"hipaa,omitempty"`
		NIST    []string `json:"nist_800_53,omitempty"`
		PCI_DSS []string `json:"pci_dss,omitempty"`
		TSC     []string `json:"tsc,omitempty"`
	} `json:"rule,omitempty"`

	// Location/decoder
	Location string `json:"location,omitempty"`
	Decoder  struct {
		Name   string `json:"name,omitempty"`
		Parent string `json:"parent,omitempty"`
	} `json:"decoder,omitempty"`

	// Input/data
	Input struct {
		Type string `json:"type,omitempty"`
	} `json:"input,omitempty"`

	// Predecoded fields that might be present
	PredecodeTimestamp string `json:"predecode_timestamp,omitempty"`
	PredecodeHostname  string `json:"predecode_hostname,omitempty"`
	PredecodeProgram   string `json:"predecode_program_name,omitempty"`

	// Full log and previous log
	FullLog     string `json:"full_log,omitempty"`
	PreviousLog string `json:"previous_log,omitempty"`

	// Data fields - these vary greatly by log type
	Data json.RawMessage `json:"data,omitempty"`

	// SysCheck (File Integrity Monitoring)
	SysCheck json.RawMessage `json:"syscheck,omitempty"`

	// Vulnerability detector
	Vulnerability json.RawMessage `json:"vulnerability,omitempty"`

	// AWS/Cloud logs
	AWS   json.RawMessage `json:"aws,omitempty"`
	Azure json.RawMessage `json:"azure,omitempty"`
	GCP   json.RawMessage `json:"gcp,omitempty"`

	// Security events
	Win struct {
		System    json.RawMessage `json:"system,omitempty"`
		EventData json.RawMessage `json:"eventdata,omitempty"`
	} `json:"win,omitempty"`

	// Additional dynamic fields using map for unknown structure
	Extra map[string]json.RawMessage `json:"-"`
}
