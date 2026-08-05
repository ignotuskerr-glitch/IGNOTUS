package protocol

type Request struct {
	ID        string `json:"id"`
	Host      string `json:"host"`
	Ports     []int  `json:"ports"`
	TimeoutMS int    `json:"timeout_ms"`
}

type PortResult struct {
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
	Banner string `json:"banner,omitempty"`
}

type HTTPResult struct {
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Server     string `json:"server,omitempty"`
	FinalURL   string `json:"final_url,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

type Response struct {
	ID         string       `json:"id"`
	Host       string       `json:"host"`
	IPs        []string     `json:"ips,omitempty"`
	CNAME      string       `json:"cname,omitempty"`
	Ports      []PortResult `json:"ports,omitempty"`
	HTTP       *HTTPResult  `json:"http,omitempty"`
	Error      string       `json:"error,omitempty"`
	DurationMS int64        `json:"duration_ms"`
}
