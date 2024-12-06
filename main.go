package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/juanmoliva/ureal/pkg/requests"

	flag "github.com/spf13/pflag"
)

type Host struct {
	scheme string
	domain string
	port   string
}

type CalibrationMethod int

const (
	CHARS_LENGTH CalibrationMethod = iota
	WORDS_LENGTH
	CUSTOM
)

var NotDetected = "NOT_DETECTED"

type Base404ResponseData struct {
	calibrationMethod CalibrationMethod

	StatusCode string

	// CHARS_LENGTH
	charsLength int

	// WORDS_LENGTH
	wordsLength int

	// CUSTOM
	first150Chars string
	last150Chars  string
	avgLength     int
}

func main() {

	var DebugMode bool
	var Silent bool
	var Proxy string
	var Output string
	var PrettyPrint bool
	var Threads int

	flag.BoolVarP(&DebugMode, "debug", "d", false, "enable debug mode")
	flag.BoolVarP(&Silent, "silent", "s", false, "silent mode (only output URLs)")
	flag.StringVar(&Proxy, "proxy", "", "proxy URL")
	flag.StringVarP(&Output, "output", "o", "", "output file")
	flag.BoolVar(&PrettyPrint, "pretty", false, "output in pretty format (default json lines).")
	flag.IntVarP(&Threads, "threads", "t", 5, "number of threads, default 5")

	flag.Parse()

	var outf *os.File
	// output
	if Output != "" {
		var err error
		outf, err = os.Create(Output)
		if err != nil {
			fmt.Println(fmt.Errorf("error creating output file: %w", err))
			return
		}
		defer outf.Close()
	}

	if Threads < 1 {
		fmt.Println("Threads must be greater than 0")
		os.Exit(1)
	}

	sc := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)

	hostBaseResponses := make(map[Host]Base404ResponseData)
	hostBaseResponsesMutex := sync.RWMutex{}

	httpFollowsSameHostRedirects := make(map[Host]int)
	httpFollowsSameHostRedirectsMutex := sync.RWMutex{}

	domainFollowsWWWRedirects := make(map[string]int)
	domainFollowsWWWRedirectsMutex := sync.RWMutex{}

	hostErrors := make(map[Host]int)
	hostErrorsMutex := sync.RWMutex{}
	yes := 1
	no := -1

	// www.example.com
	//  --> found 404 with word count  X times.
	hostReal404WordCounts := make(map[Host]map[int]int)
	real404WordCountThreshold := 3

	hostReal404WordCountsMutex := sync.RWMutex{}

	seenRealHashes := make(map[string]int)
	seenRealHashesMutex := sync.RWMutex{}
	seenRealHashesThreshold := 3

	httpClientConfig := requests.HttpClientConfig{
		DebugMode: DebugMode,
		Proxy:     Proxy,
	}

	var httpClients []requests.HttpClient
	for i := 0; i < Threads; i++ {
		httpClients = append(httpClients, requests.NewClient(httpClientConfig))
	}

	urls := make(chan string)
	output := make(chan OutU)

	var basePathA = "/nonexisting"
	var basePathB = "/nonexistingy/neitherbutabigpath"
	var basePathC = "/nonexistingalsowithparamsandalsobigpath?myparamname=myparamvalue"

	var wg sync.WaitGroup
	for i := 0; i < Threads; i++ {
		wg.Add(1)

		go func(i int) {
			for u := range urls {
				// get the domain from the host
				host, err := getHost(u)
				if err != nil {
					if DebugMode {
						fmt.Println(fmt.Errorf("error getting host for url: %w", err))
					}
					continue
				}

				hostErrorsMutex.Lock()
				if hostErrors[host] == yes {

					if DebugMode {
						fmt.Println("skipping host because of previous error: ", host)
					}

					hostErrorsMutex.Unlock()
					continue
				}
				hostErrorsMutex.Unlock()

				// check if www. has same base response

				httpFollowsSameHostRedirectsMutex.Lock()
				// check if the host has been checked for same host redirects
				if host.scheme == "http" {
					if _, ok := httpFollowsSameHostRedirects[host]; !ok {
						httpReqConfig := requests.HttpReqConfig{
							HTTPMethod: requests.GET,
						}

						httpResp, err := httpClients[i].Make(host.String()+basePathA, httpReqConfig)
						if err != nil {
							httpFollowsSameHostRedirects[host] = no
						} else if strings.Contains(httpResp.GetFinalRedirect(), "https://"+host.domain) {
							httpFollowsSameHostRedirects[host] = yes
						} else {
							httpFollowsSameHostRedirects[host] = no
						}

						if DebugMode {
							fmt.Println("checked for same host redirects: ", host, httpFollowsSameHostRedirects[host])
						}
					}
				}

				if httpFollowsSameHostRedirects[host] == yes {
					u = strings.Replace(u, "http://", "https://", 1)
					host.scheme = "https"
				}
				httpFollowsSameHostRedirectsMutex.Unlock()

				domainFollowsWWWRedirectsMutex.Lock()
				if domainFollowsWWWRedirects[host.domain] == yes {
					u = strings.Replace(u, host.domain, "www."+host.domain, 1)
					host.domain = "www." + host.domain
				}
				domainFollowsWWWRedirectsMutex.Unlock()

				hostBaseResponsesMutex.Lock()
				if _, ok := hostBaseResponses[host]; !ok {
					// get the base response for the host

					if DebugMode {
						fmt.Println("host not found: ", host, " adding to map")
					}
					base404 := Base404ResponseData{}

					httpReqConfig := requests.HttpReqConfig{
						HTTPMethod: requests.GET,
					}

					// requests to
					//  A		/nonexisting
					//  B		/nonexistingy/neitherbutabigpath
					//  C		/nonexistingalsowithparamsandalsobigpath?myparamname=myparamvalue

					// Same HTTP status for all is expected, otherwise print warning.
					// 	 --> Different status when adding parameters?
					// See content-length for all.
					//		same? --> CHARS_LENGTH match.
					// 	else...
					// See words for all.
					//		same? --> WORDS_LENGTH match.
					// 	else...
					// Gather difference in three responses:
					//		- "normalized length" --> tolerance of +- 10% of chars.
					// 		- first 150 chars.
					// 		- last 150 chars.

					AResp, err := httpClients[i].Make(host.String()+basePathA, httpReqConfig)
					if err != nil {

						if DebugMode {
							fmt.Println(fmt.Errorf("error making request on base response to %s: %w", host.String()+basePathA, err))
						}

						hostErrorsMutex.Lock()
						hostErrors[host] = yes
						hostErrorsMutex.Unlock()

						hostBaseResponsesMutex.Unlock()

						continue
					}

					if !strings.Contains(host.domain, "www.") {
						finalRedir := AResp.GetFinalRedirect()
						if DebugMode {
							fmt.Println("final redirect: ", finalRedir)
						}
						if strings.Contains(finalRedir, "http://www."+host.domain) || strings.Contains(finalRedir, "https://www."+host.domain) {
							domainFollowsWWWRedirectsMutex.Lock()
							domainFollowsWWWRedirects[host.domain] = yes
							domainFollowsWWWRedirectsMutex.Unlock()

							if DebugMode {
								fmt.Println("domain follows www redirect: ", host.domain)
							}

						} else {
							domainFollowsWWWRedirectsMutex.Lock()
							domainFollowsWWWRedirects[host.domain] = no
							domainFollowsWWWRedirectsMutex.Unlock()
						}
					}

					BResp, err := httpClients[i].Make(host.String()+basePathB, httpReqConfig)
					if err != nil {
						if DebugMode {
							fmt.Println(fmt.Errorf("error making request on base response to %s: %w", host.String()+basePathB, err))
						}
						hostBaseResponsesMutex.Unlock()
						continue
					}

					CResp, err := httpClients[i].Make(host.String()+basePathC, httpReqConfig)
					if err != nil {
						if DebugMode {
							fmt.Println(fmt.Errorf("error making request on base response to %s: %w", host.String()+basePathC, err))
						}
						hostBaseResponsesMutex.Unlock()
						continue
					}

					if AResp.Status != BResp.Status || BResp.Status != CResp.Status {
						if DebugMode {
							fmt.Printf("Different status codes detected for %s: %s - %s - %s", host.String(), AResp.Status, BResp.Status, CResp.Status)
						}
						base404.StatusCode = NotDetected
					} else {
						base404.StatusCode = AResp.Status
					}

					lenBodies := make([]int, 3)
					lenBodies[0] = len(AResp.Body)
					lenBodies[1] = len(BResp.Body)
					lenBodies[2] = len(CResp.Body)

					if allEqual(lenBodies...) {
						base404.calibrationMethod = CHARS_LENGTH
						base404.charsLength = lenBodies[0]
					} else {

						lenWords := make([]int, 3)
						lenWords[0] = len(strings.Fields(string(AResp.Body)))
						lenWords[1] = len(strings.Fields(string(BResp.Body)))
						lenWords[2] = len(strings.Fields(string(CResp.Body)))

						if allEqual(lenWords...) {
							base404.calibrationMethod = WORDS_LENGTH
							base404.wordsLength = lenWords[0]

						} else {
							base404.calibrationMethod = CUSTOM

							first150Chars := make([]string, 3)
							last150Chars := make([]string, 3)

							first150Chars[0] = string(AResp.Body)[:min(150, len(AResp.Body))]
							first150Chars[1] = string(BResp.Body)[:min(150, len(BResp.Body))]
							first150Chars[2] = string(CResp.Body)[:min(150, len(CResp.Body))]

							if first150Chars[0] != first150Chars[1] || first150Chars[1] != first150Chars[2] {
								base404.first150Chars = NotDetected
							} else {
								base404.first150Chars = first150Chars[0]
							}

							last150Chars[0] = string(AResp.Body)[max(0, len(AResp.Body)-150):]
							last150Chars[1] = string(BResp.Body)[max(0, len(BResp.Body)-150):]
							last150Chars[2] = string(CResp.Body)[max(0, len(CResp.Body)-150):]

							if last150Chars[0] != last150Chars[1] || last150Chars[1] != last150Chars[2] {
								base404.last150Chars = NotDetected
							} else {
								base404.last150Chars = last150Chars[0]
							}

							// average length of the three bodies
							base404.avgLength = (lenBodies[0] + lenBodies[1] + lenBodies[2]) / 3
						}
					}

					hostBaseResponses[host] = base404

					rootPathResp, err := httpClients[i].Make(host.String(), httpReqConfig)
					if err != nil {
						if DebugMode {
							fmt.Println(fmt.Errorf("error making request to %s: %w", u, err))
						}
						hostBaseResponsesMutex.Unlock()
						continue
					}

					out := OutU{
						Url:           host.String(),
						StatusCode:    rootPathResp.Status,
						Words:         len(strings.Fields(string(rootPathResp.Body))),
						ContentLength: len(rootPathResp.Body),
						ContentType:   rootPathResp.HTTPHeaders.Get("Content-Type"),
						FinalReditect: rootPathResp.GetFinalRedirect(),
					}

					output <- out

				}

				hostBaseResponsesMutex.Unlock()

				// is the url a real one or equal to the base response?

				httpReqConfig := requests.HttpReqConfig{
					HTTPMethod: requests.GET,
				}

				resp, err := httpClients[i].Make(u, httpReqConfig)
				if err != nil {
					if DebugMode {
						fmt.Println(fmt.Errorf("error making request to %s: %w", u, err))
					}
					continue
				}

				base404 := hostBaseResponses[host]

				realone := true
				if (base404.StatusCode == NotDetected) || (resp.Status == base404.StatusCode) {
					switch base404.calibrationMethod {
					case CHARS_LENGTH:
						if len(resp.Body) == base404.charsLength {
							realone = false
						}
					case WORDS_LENGTH:
						if len(strings.Fields(string(resp.Body))) == base404.wordsLength {
							realone = false
						}
					case CUSTOM:
						if len(resp.Body) > int(float64(base404.avgLength)*0.9) && len(resp.Body) < int(float64(base404.avgLength)*1.1) {
							if string(resp.Body)[:min(150, len(resp.Body))] == base404.first150Chars && string(resp.Body)[max(0, len(resp.Body)-150):] == base404.last150Chars {
								realone = false
							}
						}
					}
				}

				if realone {

					if strings.Contains(resp.Status, "404") {
						hostReal404WordCountsMutex.Lock()
						// a "real" 404, I will save the word count and if found more than X times will skip it.
						words := len(strings.Fields(string(resp.Body)))

						if _, ok := hostReal404WordCounts[host]; !ok {
							hostReal404WordCounts[host] = make(map[int]int)
						}

						if _, ok := hostReal404WordCounts[host][words]; !ok {
							hostReal404WordCounts[host][words] = 1
						}

						hostReal404WordCounts[host][words]++

						if hostReal404WordCounts[host][words] > real404WordCountThreshold {
							realone = false
						}
						hostReal404WordCountsMutex.Unlock()
					} else {
						seenRealHashesMutex.Lock()

						// not a 404, If seen the response before, skip it.
						hash, err := resp.GetHash()

						if err != nil {
							fmt.Println(fmt.Errorf("error getting hash for response: %w", err))
						} else {
							if _, ok := seenRealHashes[hash]; ok {
								seenRealHashes[hash]++
								if seenRealHashes[hash] > seenRealHashesThreshold {
									if DebugMode {
										fmt.Println("seen hash before: ", hash, " ", seenRealHashes[hash], " times, for url: ", u, " skipping...")
									}
									realone = false
								}
							} else {
								seenRealHashes[hash] = 1
							}
						}
						seenRealHashesMutex.Unlock()
					}

				}

				if realone {
					out := OutU{
						Url:           u,
						StatusCode:    resp.Status,
						Words:         len(strings.Fields(string(resp.Body))),
						ContentLength: len(resp.Body),
						ContentType:   resp.HTTPHeaders.Get("Content-Type"),
						FinalReditect: resp.GetFinalRedirect(),
					}
					output <- out
				}

			}

			wg.Done()
		}(i)
	}

	// Output worker
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		for o := range output {
			writeToOutput(outf, o, Silent, PrettyPrint)
		}
		outputWG.Done()
	}()

	// Close the output channel when the HTTP workers are done
	go func() {
		wg.Wait()
		close(output)
	}()

	for sc.Scan() {
		u := sc.Text()

		urls <- u
	}

	close(urls)

	// check there were no errors reading stdin (unlikely)
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
	}

	// Wait until the output waitgroup is done
	outputWG.Wait()

}

// getHost returns the host object.
func getHost(u string) (h Host, err error) {
	uu, err := url.Parse(u)
	if err != nil {
		return Host{}, fmt.Errorf("error parsing url: %w", err)
	}

	p := ""
	if uu.Port() != "" {
		if (uu.Port() != "80" && uu.Scheme == "http") || (uu.Port() != "443" && uu.Scheme == "https") {
			p = uu.Port()
		}
	}
	return Host{
		scheme: uu.Scheme,
		domain: uu.Host,
		port:   p,
	}, nil
}

func (h Host) String() string {
	if h.port == "" || (h.port == "80" && h.scheme == "http") || (h.port == "443" && h.scheme == "https") {
		return fmt.Sprintf("%s://%s", h.scheme, h.domain)
	}
	return fmt.Sprintf("%s://%s:%s", h.scheme, h.domain, h.port)
}

func allEqual(vals ...int) bool {
	for i := 1; i < len(vals); i++ {
		if vals[i] != vals[0] {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type OutU struct {
	Url           string `json:"url"`
	StatusCode    string `json:"status_code"`
	Words         int    `json:"words"`
	ContentLength int    `json:"content_length"`
	FinalReditect string `json:"final_redirect"`
	ContentType   string `json:"content_type"`
}

func writeToOutput(outf *os.File, data OutU, silent bool, prettyPrint bool) {
	print := data.Url
	if !silent {
		if !prettyPrint {
			json, err := json.Marshal(data)
			if err != nil {
				log.Printf("Error marshaling result: %v", err)
			} else {
				print = string(json)
			}
		} else {
			print = fmt.Sprintf("%s - %d words - %d length - %s - %s - final redirect: %s", data.StatusCode, data.Words, data.ContentLength, data.ContentType, data.Url, data.FinalReditect)
		}
	}
	if outf != nil {
		outf.WriteString(print + "\n")
	} else {
		fmt.Println(print)
	}
}
