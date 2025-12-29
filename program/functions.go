package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func VerifyInsecureProtocols(protocolVersion string, protocolsName string) bool {
	insecureProtocols := []string{"1.0", "1.1","SSL","SSLv2","SSLv2"}
	for _, val := range insecureProtocols  {
		if protocolVersion == val || protocolsName == val {
			return true
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


func TimeCheckerStatusProgress(response *SSLResponse,statusCode int){
	stopper:=true
	for stopper {
		if statusCode == 429 || statusCode == 529{
			fmt.Println("HOLA")
		}
		if response.Status!="READY" && response.Status!="ERROR"{
			checkState := VerifyDomain(response.Host,false)
			fmt.Println("EJECUTANDO")
			*response=checkState
			time.Sleep(15 * time.Second)
			continue
		}
		stopper=false
	}
}

func CountGrades(endpoints EndpointResponse) map[string]int {
	grades := make(map[string]int)
	grades["A+"] = 0
	grades["A"]  = 0
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


func CountEndpoints(endpoints EndpointResponse)int {
	return len(endpoints)
}

func CountInsecuritiesProtocol(protocolsVersion Protocols) bool {
	for _, value := range protocolsVersion {
		if VerifyInsecureProtocols(value.Version, value.Name) {
			return true
		}
	}
	return false
}

func VerifyDomain(domain string,startNew bool) SSLResponse {

	var resp *http.Response
	var err error

	resp, err = http.Get("https://api.ssllabs.com/api/v2/analyze?host=" + domain + "&all=on")

	if startNew{
		resp, err = http.Get("https://api.ssllabs.com/api/v2/analyze?host=" + domain + "&all=on&startNew")
	}
	code :=resp.StatusCode
	if err != nil {
		fmt.Println("Error en la petición:", err)
		return SSLResponse{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error leyendo respuesta:", err)
		return SSLResponse{}
	}

	var result SSLResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		fmt.Println("Error parseando JSON:", err)
		return SSLResponse{}
	}
	fmt.Println(code)
	TimeCheckerStatusProgress(&result,code)
	return result
}



func CheckAvailability()SSLResponse{
	var resp *http.Response
	var err error

	resp, err = http.Get("https://api.ssllabs.com/api/v2/info")
		if err != nil {
		fmt.Println("Error en la petición:", err)
		return SSLResponse{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error leyendo respuesta:", err)
		return SSLResponse{}
	}

	var result SSLResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		fmt.Println("Error parseando JSON:", err)
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

