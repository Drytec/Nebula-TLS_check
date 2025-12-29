package main
import(
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	state := StateInputDomain
	reader := bufio.NewReader(os.Stdin)

	var lastResult SSLResponse
	var domain string
	var domainVerified []string
	for state != StateExit {
		switch state {

		case StateInputDomain:
			fmt.Print("Enter domain to scan: ")
			domain, _ = reader.ReadString('\n')
			domain = strings.TrimSpace(domain)
			domainVerified=append(domainVerified,domain )
			state = StateScanning

		case StateScanning:
			fmt.Println("\nScanning:", domain)
			lastResult = VerifyDomain(domain, true)
			state = StateResults

		case StateResults:
			PrintResults(lastResult)
			state = StateMenu

		case StateMenu:
			state = menu(reader)
		case StateVerifiedDomains:
			PrintDomains(domainVerified)
			state = StateMenu
		}
	}

	fmt.Println("Bye")
}

	
	

