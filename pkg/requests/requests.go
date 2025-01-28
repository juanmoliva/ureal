package requests

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HttpClientConfig is the configuration for a HTTP client.
type HttpClientConfig struct {
	AuthorizationHeader string
	DebugMode           bool
	Proxy               string
}

// HttpClient is a HTTP client.
type HttpClient struct {
	c         http.Client
	Transport *loggingTransport
	Config    HttpClientConfig
}

type loggingTransport struct {
	Transport http.RoundTripper
	Redirects []*url.URL
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.Redirects = append(t.Redirects, req.URL) // Log each URL before it's executed
	return t.Transport.RoundTrip(req)
}

// NewClient creates a new HTTP client with the given configuration.
func NewClient(config HttpClientConfig) HttpClient {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			Renegotiation:      tls.RenegotiateOnceAsClient,
			Certificates:       []tls.Certificate{},
		},
	}

	tr := &loggingTransport{
		Transport: transport,
		Redirects: []*url.URL{},
	}

	if config.Proxy != "" {
		proxyUrl, err := url.Parse(config.Proxy)
		if err != nil {
			fmt.Println("Error parsing proxy URL")
		} else {
			transport.Proxy = http.ProxyURL(proxyUrl)
		}
	}
	return HttpClient{
		c: http.Client{
			Timeout:   time.Second * 30,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Allow up to 3 redirects
				if len(via) >= 3 {
					// Stop following redirects after 3
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		Transport: tr,
		Config:    config,
	}
}

// HttpMethod is the HTTP method of a HTTP request.
type HttpMethod int

const (
	GET HttpMethod = iota
	POST
	PUT
	DELETE
	PATCH
)

var HttpMethodStringMap = map[HttpMethod]string{
	GET:    "GET",
	POST:   "POST",
	PUT:    "PUT",
	DELETE: "DELETE",
	PATCH:  "PATCH",
}

// HttpReqConfig is the configuration for a HTTP request.
//
// HTTPMethod is the HTTP method of the request.
// ContentType is the content type of the request. (for non GET requests)
// Body is the body of the request. (for non GET requests)
type HttpReqConfig struct {
	HTTPMethod  HttpMethod `json:"httpMethod"`
	ContentType string     `json:"contentType"`
	Canary      string     `json:"canary"`
	Protocol    string     `json:"protocol"`
	Body        string     `json:"body"`
	HTTPHeaders map[string]string
}

// HttpResponse is the response from a HTTP request.
type HttpResponse struct {
	Status            string
	Body              []byte
	ContentType       string
	HTTPHeaders       http.Header
	ReqUri            string
	ReqRaw            string
	ChainOfRedirects  []string
	ReqConfig         HttpReqConfig
	Canary            string
	CanaryReflections int
}

// Make a HTTP request to the given URL, using the given configuration.
func (httpClient HttpClient) Make(u string, config HttpReqConfig) (resp HttpResponse, err error) {
	// empty the redirects
	defer func() {
		httpClient.Transport.Redirects = []*url.URL{}
	}()

	if httpClient.Config.DebugMode {
		defer func() {
			if err != nil {
				fmt.Printf("Error making request to: %s, error: %s\n", u, err)
			}
		}()
	}

	r, err := httpClient.makeHTTP(u, config)
	if err != nil {
		return HttpResponse{}, err
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return HttpResponse{}, err
	}
	defer r.Body.Close()

	redirectUrls := []string{}
	for _, u := range httpClient.Transport.Redirects {
		redirectUrls = append(redirectUrls, u.String())
	}

	var reflections int
	if config.Canary != "" {
		reflections = strings.Count(string(body), config.Canary)
	}

	resp = HttpResponse{
		r.Status,
		body,
		r.Header.Get("Content-Type"),
		r.Header,
		u,
		"",
		redirectUrls,
		config,
		config.Canary,
		reflections,
	}

	return resp, nil

}

var lookalikeBrowserHeaders = map[string]string{
	"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
	"Accept-Language":           "es-ES,es;q=0.9,en;q=0.8",
	"Sec-Fetch-Dest":            "document",
	"Sec-Fetch-Mode":            "navigate",
	"Sec-Fetch-Site":            "none",
	"Sec-Fetch-User":            "?1",
	"Upgrade-Insecure-Requests": "1",
	"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	"sec-ch-ua":                 "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"",
	"sec-ch-ua-mobile":          "?0",
	"sec-ch-ua-platform":        "\"Windows\"",
}

func (httpClient HttpClient) makeHTTP(url string, config HttpReqConfig) (r *http.Response, err error) {
	var reqBody io.Reader
	if config.Body == "" {
		reqBody = nil
		if config.HTTPMethod != GET {
			reqBody = strings.NewReader("{}")
		}
	} else {
		reqBody = strings.NewReader(config.Body)
	}

	httpMethod := HttpMethodStringMap[config.HTTPMethod]
	req, err := http.NewRequest(httpMethod, url, reqBody)
	if err != nil {
		return nil, err
	}

	for k, v := range config.HTTPHeaders {
		req.Header.Set(k, v)
	}

	for k, v := range lookalikeBrowserHeaders {
		req.Header.Set(k, v)
	}

	if config.ContentType != "" {
		req.Header.Set("Content-Type", config.ContentType)
	} else if config.HTTPMethod != GET {
		// make default content type application/json
		req.Header.Set("Content-Type", "application/json")
	}

	if httpClient.Config.AuthorizationHeader != "" {
		header := strings.Split(httpClient.Config.AuthorizationHeader, ":")
		req.Header.Set(header[0], strings.Join(header[1:], ":"))
	}

	r, err = httpClient.c.Do(req)
	if err != nil {
		return nil, err
	}

	return r, nil
}

// GetFinalRedirect returns the final URL after all redirects, without the query parameters or hash.
func (resp HttpResponse) GetFinalRedirect() string {
	if len(resp.ChainOfRedirects) == 0 {
		return resp.ReqUri
	}

	finalUrl := resp.ChainOfRedirects[len(resp.ChainOfRedirects)-1]
	u, err := url.Parse(finalUrl)
	if err != nil {
		return finalUrl
	}

	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (resp HttpResponse) GetHash() (string, error) {
	h := fnv.New128a()

	_, err := h.Write([]byte(resp.Status))
	if err != nil {
		return "", fmt.Errorf("error writing status code to hash: %w", err)
	}

	limit := 1000
	if len(resp.Body) < 1000 {
		limit = len(resp.Body)
	}

	_, err = h.Write([]byte(resp.Body[:limit]))
	if err != nil {
		return "", fmt.Errorf("error writing body to hash: %w", err)
	}

	_, err = h.Write(IntToBytes(len(resp.Body)))
	if err != nil {
		return "", fmt.Errorf("error writing body to hash: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func IntToBytes(n int) []byte {
	// Create a byte slice with the size of an int (which depends on the architecture)
	// Typically, it is either 4 bytes for 32-bit systems or 8 bytes for 64-bit systems.
	bytes := make([]byte, 4) // Assuming a 32-bit int, for 64-bit, use 8

	// Convert int to []byte
	binary.BigEndian.PutUint32(bytes, uint32(n)) // Use PutUint64 for 64-bit
	return bytes
}

func (resp *HttpResponse) GetXssSources() (out []interface{}) {
	// strings to find xss sources. non case sensitive.
	domXssStrings := []string{
		"location.search",
		"location.hash",
		"searchparam",
		"urlsearch",
		"urlparam",
		"postmessage",
		"istener('message",
		"istener(\"message)",
	}

	for _, domXssString := range domXssStrings {
		if strings.Contains(strings.ToLower(string(resp.Body)), domXssString) {
			out = append(out, domXssString)
		}
	}

	return out
}
