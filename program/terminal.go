package main
import (
	"bufio"
	"fmt"
	"strings"
)

func menu(reader *bufio.Reader) AppState {
	fmt.Println("\nOptions:")
	fmt.Println("1) Scan another domain")
	fmt.Println("2) Show results again")
	fmt.Println("3) Exit")
	fmt.Println("4) View domains verified")
	fmt.Print("> ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		return StateInputDomain
	case "2":
		return StateResults
	case "3":
		return StateVerifiedDomains
		
	case "4","exit":
		return StateExit
		
	default:
		fmt.Println("Invalid option")
		return StateMenu
	}
}

func PrintDomains(domains []string){
	fmt.Println(domains)
}

func PrintResults(result SSLResponse){	
	var vulns []string

								
	for _,endpoints:= range result.Endpoints{
		RegisterVulns(endpoints.Details,&vulns)
	}
	var globalScore = GlobalScore(
						ScoreVulns(vulns),
						ScoreGrade(CountGrades(result.Endpoints)),
						ScoreProtocols(result.Endpoints),
						CountGrades(result.Endpoints),vulns) 
	fmt.Println("Host:", result.Host)
	fmt.Println("State:", result.Status)
	if result.Status=="ERROR"{
		fmt.Println("Error reason:", result.StatusMessage)
	}
	ScoreProtocols(result.Endpoints)
	fmt.Println("Vulns Detected:",vulns)
	fmt.Println("Protocols Grade:",CountGrades(result.Endpoints))
	fmt.Println("Grades Score:", ScoreGrade(CountGrades(result.Endpoints)))
	fmt.Println("Protocols Score:",ScoreProtocols(result.Endpoints))
	fmt.Println("Vulns Score:",ScoreVulns(vulns))
	fmt.Println("Domain Score:",globalScore)
	fmt.Println("Domain Clasification",ClasificationFinal(globalScore))
}