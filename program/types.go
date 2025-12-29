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
	//Suites    Suites   `json:"suites"`

	// Vulnerabilidades críticas
	VulnBeast  bool `json:"vulnBeast"`
	Heartbleed bool `json:"heartbleed"`
	Poodle     bool `json:"poodle"`
	Freak      bool `json:"freak"`
	Logjam     bool `json:"logjam"`

	// TLS features
	ForwardSecrecy int  `json:"forwardSecrecy"`
	SupportsRc4    bool `json:"supportsRc4"`
	Rc4Only        bool `json:"rc4Only"`

	// Renegociación
	RenegSupport int `json:"renegSupport"`

	// OCSP / certificados
	OcspStapling bool `json:"ocspStapling"`
	HasSct       int  `json:"hasSct"`
}
/*
type Suites struct {
	List       []Suite `json:"list"`
	Preference bool    `json:"preference"`
}

type Suite struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	CipherStrength int    `json:"cipherStrength"`
	DhStrength     int    `json:"dhStrength"`
	EcdhBits       int    `json:"ecdhBits"`
	InsecureSuite *int   `json:"q"` 
}*/

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
