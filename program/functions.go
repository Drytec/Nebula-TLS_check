package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type SSLResponse struct {
	Status        string           `json:"status"`
	StatusMessage string           `json:"statusMessage"`
	Host          string           `json:"host"`
	Endpoints     EndpointResponse `json:"endpoints"`
}

type EndpointResponse []struct {
	Grade string `json:"grade"`
	//IpAddress            string          `json:"ipAddress"`
	//StatusDetailsMessage string          `json:"statusDetailsMessage"`
	Details EndpointDetails `json:"details"`
}

type EndpointDetails struct {
	Protocols Protocols `json:"protocols"`
	VulnBeast string    `json:"vulnBeats"`
}
type Protocols []struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	V2SuitesDisabled string `json:"v2SuitesDisabled"`
	Q                string `json:"q"`
}

func VerifyInsecureProtocolsVersion(protocolVersion string) bool {
	insecureProtocols := [2]string{"1.0", "1.1"}
	for _, val := range insecureProtocols {
		if protocolVersion == val {
			return true
		}
	}
	return false
}
func VerifyInsecureProtocolsSSl(protocolsName string) bool {
	insecureProtocols := [1]string{"SSL"}
	for _, value := range insecureProtocols {
		if protocolsName == value {
			return true
		}
	}
	return false
}

func CountInsecuritiesEndpoint(endpoints EndpointResponse) int {
	counterTotal := 0
	for _, endpoint := range endpoints {
		counterTotal = counterTotal + CountInsecuritiesProtocol(endpoint.Details.Protocols)
	}
	return counterTotal
}

func CountInsecuritiesProtocol(protocolsVersion Protocols) int {
	counterProtocol := 0
	for _, value := range protocolsVersion {
		if VerifyInsecureProtocolsVersion(value.Version) || VerifyInsecureProtocolsSSl(value.Name) {
			counterProtocol++
		}
	}
	return counterProtocol
}

func VerifyDomain(domain string) string {
	//https://api.ssllabs.com/api/v2/analyze?host=" + domain+"&all=on&startNew
	resp, err := http.Get("https://api.ssllabs.com/api/v2/analyze?host=" + domain + "&all=on")
	if err != nil {
		fmt.Println("Error en la petición:", err)
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error leyendo respuesta:", err)
		return ""
	}

	var result SSLResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		fmt.Println("Error parseando JSON:", err)
		return ""
	}
	x := result.Endpoints
	totalinsecure := CountInsecuritiesEndpoint(x)
	fmt.Println("Host:", result.Host)
	fmt.Println("Estado:", result.Status)
	fmt.Println("Host:", result.StatusMessage)
	fmt.Println("Endpoints", result.Endpoints)

	fmt.Println("InsecureProtocols", totalinsecure)

	return result.Status
}
