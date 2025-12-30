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
	"F":  0,
	"T":  0,
	"M":  0,
	}	
	for key,value :=range weights{
		totalScore = totalScore +(value*grades[key])/countGrades
		switch key{
			case "F", "M", "T":
				if value>0{
					totalScore=0
				}
			default:
				continue	
		}
	}
	return totalScore
}

func ScoreProtocols(endpoints EndpointResponse)int{
	totalScore:=100
	securityFail:=totalScore/len(endpoints)
	for _,endpoint := range endpoints{
		condition:=VerifyInsecureProtocols(endpoint.Details.Protocols)
			if condition{
				totalScore=totalScore-securityFail
			}
	}
	return totalScore
}

func ScoreVulns(vulnsDetected []string)int{
	totalScore:=100
	if len(vulnsDetected)>0{
		totalScore=0
	}
	return totalScore
}

func GlobalScore(scoreVulns,scoreGrade,scoreProtocols int) int{
	totalScore:=scoreGrade*scoreVulns*scoreProtocols
	return totalScore
}