package main

import (
	"io/ioutil"
	"fmt"
	"log"
	"os/exec"
	"os"
	"strings"
)

func main() {

	switch len(os.Args) {
	case 1:
		fmt.Println("Usage: ", "createCSR", "<JKS file> <alias name>")
		fmt.Println("Usage: ", "createCSR", "<JKS file>")

	case 2:
		jks := os.Args[1]
		aliasList := getAliasList(jks)

		printAliasNames(aliasList)

		for _, alias := range aliasList {
			GenerateCSRFromJKS(jks, alias)
		}

		giveCAInfo()

	case 3:
		jks := os.Args[1]
		alias := os.Args[2]

		GenerateCSRFromJKS(jks, alias)
		giveCAInfo()

	default:
		fmt.Println("Incorrect number of arguments.")
		fmt.Println("Usage: ", "createCSR", "<JKS file> <alias name>")
		fmt.Println("Usage: ", "createCSR", "<JKS file>")
	}
}

func getAliasList(jks string) []string {
	output := execute("keytool -v -list -storepass password -keystore " + jks + " | grep Alias")
	temp := strings.SplitAfter(strings.TrimSpace(output), "\n")

	var aliasList []string
	for _, alias := range temp {
		aliasList = append(aliasList, strings.TrimSpace(strings.Split(alias, ":")[1]))
	}

	return aliasList
}

func execute(cmd string) (output string) {
    out, err := exec.Command("bash","-c",cmd).Output()

	if err != nil {
		log.Fatal("Unable to execute command " + cmd)
	}

	return strings.TrimSpace(string(out))
}

func GenerateCSRFromJKS(jks, alias string) {
	// TODO: As this program is dependent on 'OpenSSL 1.0.2k-fips  26 Jan 2017' version, warn if a different version of openssl is used.


	// TODO: CLEANUP: Delete generated file.
	createCertFromJKS(jks, alias)
	// fmt.Println("Certificate associated to " + alias + " extracted.")

	pemFile := alias + ".pem"
	subject := getSubjectFromCert(pemFile)
	// fmt.Println("Subject extracted from certificate.")

	san := getSANFromCert(pemFile)
	// fmt.Println("Subject Alternative Name (SAN) extracted from certificate.")

	createConfigFile(alias, subject, san)
	// fmt.Println("Config file " + alias + ".ini created.")

	createCSR(alias)
	fmt.Println("\nCertificated signing request file " + alias + ".csr created.")
	printFile(alias + ".csr")
	// cleanup()
}

func createConfigFile(alias string, subject Subject, san San) {
	f, err := os.Create(alias + ".ini")
    check(err)
	
	f.WriteString("[req]\n")
	f.WriteString("default_bits=2048\n")
	f.WriteString("prompt=no\n")
	f.WriteString("encrypt_key=no\n")
	f.WriteString("default_md=sha256\n")
	f.WriteString("distinguished_name=dn\n")

	sanPresent := len(san.dnsOrIpAddress) > 0

	if sanPresent {
		f.WriteString("req_extensions=req_ext\n\n")
	}

	if len(subject.fields) <= 0 {
		log.Fatal("Subject fields are empty, cannot proceed for CSR creation.")
	}

	f.WriteString("[dn]\n")
	for _, field := range subject.fields {
		f.WriteString(field + "\n")
	}

	if sanPresent {
		f.WriteString("\n[req_ext]\n")
		f.WriteString("subjectAltName=")

		count := 0
		for _, sanField := range san.dnsOrIpAddress {
			count++

			f.WriteString(sanField)

			if count < len(san.dnsOrIpAddress) {
				f.WriteString(",")
			}
		}
	}

	f.WriteString("\n")
    defer f.Close()
}

func createCSR(alias string) {
	commandArgs := getCmdArgs("req -new -out " + alias + ".csr " + "-keyout " + alias + ".key " + "-config " + alias + ".ini")
    _, err := exec.Command("openssl", commandArgs...).Output()

	if err != nil {
		log.Fatal("Could not create CSR: ", err)
	} 
}

func createCertFromJKS(jks, alias string) {
	//TODO: Try with a different storepass. If password does not work give a easy to understand error message.
    commandArgs := getCmdArgs("-export -alias " + alias + " -file " + alias + ".pem " + "-keystore " + jks + " -storepass password -rfc")
    _, err := exec.Command("keytool", commandArgs...).Output()
	if err != nil {
		log.Fatal("JKS file name or alias name is incorrect or you may be unlucky and the usual password to open JKS file is not working.")
	}  
}

func getSubjectFromCert(pemFile string) Subject {
    commandArgs := getCmdArgs("x509 -noout -subject -in " + pemFile + " -nameopt RFC2253")
	out, err := exec.Command("openssl", commandArgs...).Output()
	if err != nil {
		log.Fatal(err)
	}

	// Expecting string similar to subject=CN=gateway3ds-02,OU=IT,O=ING,L=Sydney,ST=NSW,C=AU
	subjectString := strings.TrimSpace(string(out))
	subjectFields := strings.SplitAfterN(subjectString, "=", 2)
	subjectFields = strings.Split(subjectFields[1], ",")

	var subject Subject

	for _, field := range subjectFields {
		subject.fields = append(subject.fields, strings.TrimSpace(field))
	}

	return subject	
}

func getSANFromCert(pemFile string) San {
	commandArgs := getCmdArgs("x509 -text -noout -certopt no_subject,no_header,no_version,no_serial,no_signame,no_validity,no_issuer,no_pubkey,no_sigdump,no_aux -in " + pemFile)
	out, err := exec.Command("openssl", commandArgs...).Output()
	if err != nil {
		log.Fatal(err)
	}

	var san San
	san.dnsOrIpAddress = make([]string, 0)
	for _, commaSplittedLines := range strings.Split(string(out), ",") {
		trimmedLines := strings.TrimSpace(commaSplittedLines)
		spaceSplittedLines := strings.Fields(trimmedLines)
		for _, spaceSplittedLine := range spaceSplittedLines {
		if strings.HasPrefix(spaceSplittedLine, "DNS") || strings.HasPrefix(spaceSplittedLine, "Address") {
				if strings.HasPrefix(spaceSplittedLine, "Address") {
					spaceSplittedLine = strings.Replace(spaceSplittedLine, "Address", "IP", 1)
				}

				san.dnsOrIpAddress = append(san.dnsOrIpAddress, spaceSplittedLine)
			}
		}
	}

	return san
}

func getCmdArgs(commandArgs string) []string {
    return strings.Fields(commandArgs)
}

func printFile(fileName string) {
    // Read file to byte slice
    data, err := ioutil.ReadFile(fileName)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(string(data))
}

func cleanup() {
	// TODO:
	fmt.Println("Intermediate files deleted.")
}

func giveCAInfo() {
	fmt.Println("For BIAB login as tau\\username to https://tpkiapps.tau.ingdirect.intranet/certsrv/ and submit CSR.")
}
	
func check(e error) {
    if e != nil {
        panic(e)
    }
}

type Subject struct {
	fields []string
}

// Struct to hold Subject Alternative Name extension
type San struct {
	dnsOrIpAddress []string
}

func printAliasNames(aliasList []string) {
	switch {
		case len(aliasList) > 1:
			fmt.Println(len(aliasList), "aliases found:-")

			for index, alias := range aliasList {
				fmt.Print(index + 1, ") ", alias, "\n")
			}

		case len(aliasList) == 1:
			fmt.Println(len(aliasList), "alias found:-")
			fmt.Println(aliasList[0])

		default:
			log.Fatal("Incorrect number of aliases. Cannot generate CSR.")
	}
}
