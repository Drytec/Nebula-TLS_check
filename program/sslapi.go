package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
	"regexp"
)


func isValidDomain(domain string) bool {
	re := regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`)
	return re.MatchString(domain)
}

func VerifyInsecureProtocols(protocols Protocols) bool {
	insecureProtocols := []string{"1.0", "1.1","SSL"}
	for _, val := range insecureProtocols  {
		for _,protocol:=range protocols{
			if protocol.Name == val || protocol.Version == val {
			return true
		}
		}
	}
	return false
}

func RegisterVulns(details  EndpointDetails,vulsList *[]string){
	checks := map[string]bool{
		"FREAK": details.Freak,
		"BEAST": details.VulnBeast,
		"POODLE": details.Poodle,
		"HEARTBLEED": details.Heartbleed,
		"LOGJAM": details.Logjam,
		"RC4":details.Rc4Only,
	}

	for name, detected := range checks {
		if len(*vulsList)<1{
			if detected  {
				*vulsList = append(*vulsList, name)
			}
		}
		for _,exist:= range *vulsList{
			if detected && exist!=name {
				*vulsList = append(*vulsList, name)
			}
		}
	}
}


func TimeCheckerStatusProgress(response *SSLResponse) {
	const (
		maxAttempts   = 20
	)
	var checkInterval = time.Second
	
	attempts := 0

	for {
		switch {
		case attempts >=15:
			checkInterval = 20 * time.Second
		case attempts >= 10:
			checkInterval = 15 * time.Second
		case attempts >= 5:
			checkInterval = 10 * time.Second
		default:
			checkInterval = 5 * time.Second
		}
		if response.Status == "READY" || response.Status == "ERROR" {
			return
		}
		if attempts >= maxAttempts {
			response.Status = "TIMEOUT"
			response.StatusMessage = "Max retry attempts reached"
			fmt.Println("Max attempts reached")
			return
		}

		fmt.Println("Scanning...")
		checkState := VerifyDomainTimer(response.Host, false)
		*response = checkState

		attempts++
		time.Sleep(checkInterval)
	}
}

func CountProtocols(endpoints EndpointResponse) map[string]int {

	normalization := map[string]map[string]string{
		"TLS": {
			"1.0": "TLS:1.0-1.1",
			"1.1": "TLS:1.0-1.1",
			"1.2": "TLS:1.2",
			"1.3": "TLS:1.3",
		},
		"SSL": {
			"2.0": "SSL:2.0",
			"3.0": "SSL:3.0",
		},
	}

	protocols := make(map[string]int)

	for _, endpoint := range endpoints {
		for _, protocol := range endpoint.Details.Protocols {

			if versions, ok := normalization[protocol.Name]; ok {
				if key, ok := versions[protocol.Version]; ok {
					protocols[key]++
				}
			}
		}
	}

	return protocols
}


func CountGrades(endpoints EndpointResponse) map[string]int {
	grades := make(map[string]int)
	grades["A"] = 0
	grades["A+"]  = 0
	grades["B"]  = 0
	grades["C"]  = 0
	grades["D"]  = 0
	grades["E"]  = 0
	grades["F"]  = 0
	grades["T"]  = 0 
	grades["M"]  = 0 

	for _, endpoint := range endpoints {
		switch endpoint.Grade {
		case "A+":
			grades["A+"]++
		case "A", "A-":
			grades["A"]++
		case "B":
			grades["B"]++
		case "C":
			grades["C"]++
		case "D":
			grades["D"]++
		case "E":
			grades["E"]++
		case "F":
			grades["F"]++
		case "T": 
			grades["T"]++
		case "M":
			grades["M"]++
		default:
			grades["F"]++
		}
	}
	return grades
}

func VerifyDomain(domain string,startNew bool) SSLResponse {

	var resp *http.Response
	var err error
	if isValidDomain(domain){
		resp, err = http.Get("https://api.ssllabs.com/api/v2/analyze?host=" + domain + "&all=on")

		if startNew{
			resp, err = http.Get("https://api.ssllabs.com/api/v2/analyze?host=" + domain + "&all=on&startNew")
		}
		if err != nil {
			fmt.Println("ERROR:", err)

			return SSLResponse{}
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("ERROR:", err)
			return SSLResponse{}
		}

		var result SSLResponse
		err = json.Unmarshal(body, &result)
		if err != nil {
			return SSLResponse{Host:"INVALID",Status:"ERROR" ,StatusMessage: err.Error()}
		}
		TimeCheckerStatusProgress(&result,)
		return result
	}
 	return SSLResponse{Host:"INVALID",Status:"ERROR" ,StatusMessage:"Invalid Domain"}
}

func VerifyDomainTimer(domain string,startNew bool) SSLResponse {

	var resp *http.Response
	var err error

	resp, err = http.Get("https://api.ssllabs.com/api/v2/analyze?host=" + domain + "&all=on")

	if err != nil {
		fmt.Println("ERROR:", err)
		return SSLResponse{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("ERROR:", err)
		return SSLResponse{}
	}

	var result SSLResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		fmt.Println("ERROR:", err)
		return SSLResponse{}
	}
	return result
}

func GetInfo() (*InfoResponse, error) {
	resp, err := http.Get("https://api.ssllabs.com/api/v2/info")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var info InfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

