package main

type AppState int

const (
	StateInputDomain AppState = iota
	StateScanning
	StateResults
	StateMenu
	StateExit
	StateVerifiedDomains
)


type SSLResponse struct {
	Status        string           `json:"status"`
	StatusMessage string           `json:"statusMessage"`
	Protocol      string 		   `json:"protocol"`
	Host          string           `json:"host"`
	Endpoints     EndpointResponse `json:"endpoints"`
}

type EndpointResponse []struct {
	Grade string `json:"grade"`
	HasWarnings bool `json:"hasWarnings"`
	StatusDetailsMessage string `json:"statusDetailsMessage"`
	Details EndpointDetails `json:"details"`
}

type EndpointDetails struct {

	Protocols Protocols `json:"protocols"`

	VulnBeast  bool `json:"vulnBeast"`
	Heartbleed bool `json:"heartbleed"`
	Poodle     bool `json:"poodle"`
	Freak      bool `json:"freak"`
	Logjam     bool `json:"logjam"`

	
	SupportsRc4    bool `json:"supportsRc4"`
	Rc4Only        bool `json:"rc4Only"`

}


type Protocols []struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	V2SuitesDisabled bool `json:"v2SuitesDisabled"`
	InsecureProtocol *int `json:"q"`
}


type InfoResponse struct {
	Version               string   `json:"version"`
	CriteriaVersion       string   `json:"criteriaVersion"`
	MaxAssessments        int      `json:"maxAssessments"`
	CurrentAssessments    int      `json:"currentAssessments"`
	NewAssessmentCoolOff  int      `json:"newAssessmentCoolOff"`
	Messages              []string `json:"messages"`
}
