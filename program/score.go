package main




func ScoreGrade( grades map[string]int)int {
	countGrades:=0
	totalScore :=0
	for _,value:=range grades{
		countGrades=countGrades+value
	}
	if countGrades==0{
		return 0
	}
	weights := map[string]int{
	"A+": 100,
	"A":  90,
	"B":  80,
	"C":  65,
	"D":  50,
	"E":  30,
	}	
	for key,value :=range weights{
		totalScore = totalScore +(value*grades[key])/countGrades
		}
	return totalScore
}

func ScoreProtocols(endpoints EndpointResponse) int {
	score := 100

	for _, ep := range endpoints {
		for _, p := range ep.Details.Protocols {
			if p.Name == "SSL" && p.Version == "2.0" {
				return 0
			}
			if p.Name == "SSL" && p.Version == "3.0" {
				score -= 40
			}
			if p.Name == "TLS" && (p.Version == "1.0" || p.Version == "1.1") {
				score -= 20
			}
		}
	}

	if score < 0 {
		score = 0
	}

	return score
}
func ScoreVulns(vulnsDetected []string)int{
	totalScore:=100
	if len(vulnsDetected)>0{
		totalScore=0
	}
	return totalScore
}

func GlobalScore(scoreVulns,scoreGrade,scoreProtocols int,grades map[string]int, vulns []string ) int{
	if HasCriticalFailure(grades, vulns) {
		return 0
	}
	totalScore:=(scoreGrade*40+scoreVulns*40+scoreProtocols*20)/100
	return totalScore
}

func ClasificationFinal(scoreTotal int) string {
	switch {
	case scoreTotal == 100:
		return "SECURE"
	case scoreTotal >= 75:
		return "STRONG"
	case scoreTotal >= 50:
		return "WEAK"
	default:
		return "INSECURE"
	}
}

func HasCriticalFailure(grades map[string]int, vulns []string) bool {
	if grades["F"] > 0 || grades["T"] > 0 || grades["M"] > 0 {
		return true
	}

	criticalVulns := map[string]bool{
		"HEARTBLEED": true,
		"POODLE":     true,
		"FREAK":      true,
		"LOGJAM":     true,
		"RC4":        true,
	}

	for _, value := range vulns {
		if criticalVulns[value] {
			return true
		}
	}

	return false
}