package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	// "time"
)

var DOMAIN_LIST = "sites.txt"

type SiteInfo struct {
	Domain     string
	Encryption string // "" = None; "TLSv1.2", etc.
	DayValid   string // first day key is valid
	Expires    string // When key expires
	Cipher     string // cipher suite being used
	// KeySize    int
	// ValidCA    bool // does key use valid CA?

}

func readSites(siteChan chan string) {
	sitesFile, err := os.Open(DOMAIN_LIST)

	if err != nil {
		fmt.Println("Couldn't read file")
		return
	}
	defer sitesFile.Close()

	fileScanner := bufio.NewScanner(sitesFile)

	for fileScanner.Scan() {
		siteChan <- fileScanner.Text()
	}

	if err := fileScanner.Err(); err != nil {
		fmt.Println("Error: ", err)
	}
}

func allowRedirect(req *http.Request, via []*http.Request) error {
	return nil
}

func processInfo(site string, resp *http.Response, err error, resultChan chan *SiteInfo) {
	r := &SiteInfo{
		Domain: site,
	}

	// second part of OR condition is bugfix for sites that redirect https -> http (like nytimes.com)

	if err != nil || resp.TLS == nil {
		fmt.Printf("Looks like %s doesn't support HTTPS (%s)\n", site, err)

		r.Encryption = ""

		resultChan <- r
	} else {
		fmt.Printf("%s is good!\n", site)

		// what TLS version is used?
		tlsCS := resp.TLS

		if tlsCS != nil {
			switch tlsCS.Version {
			case tls.VersionSSL30:
				r.Encryption = "SSLv3.0"
			case tls.VersionTLS10:
				r.Encryption = "TLSv1.0"
			case tls.VersionTLS11:
				r.Encryption = "TLSv1.1"
			case tls.VersionTLS12:
				r.Encryption = "TLSv1.2"
			default:
				log.Fatal("TLS version found, but it isn't defined?\n", tlsCS.Version)
			}
		} else {
			fmt.Printf("Weird site: %s\n TLS info: %#v\n", site, tlsCS)
			log.Fatal("WTF? There is no tls.ConnectionState, but we're encrypted? ", site)
		}

		// find certificate used in tls
		var cert *x509.Certificate
		if len(tlsCS.PeerCertificates) > 0 {
			cert = tlsCS.PeerCertificates[0]
			// fmt.Printf("Have certificate for %s\n", cert.Subject.CommonName)
		} else {
			log.Fatal("x509 certificate couldn't be found :(")
		}

		// which cipher suite is used?
		switch tlsCS.CipherSuite {
		case tls.TLS_RSA_WITH_RC4_128_SHA:
			r.Cipher = "TLS_RSA_WITH_RC4_128_SHA"
		case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
			r.Cipher = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
		case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
			r.Cipher = "TLS_RSA_WITH_AES_128_CBC_SHA"
		case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
			r.Cipher = "TLS_RSA_WITH_AES_256_CBC_SHA"
		case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
			r.Cipher = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
			r.Cipher = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
		case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			r.Cipher = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
		case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
			r.Cipher = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
		case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
			r.Cipher = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
		case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
			r.Cipher = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
		case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
			r.Cipher = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
		case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			r.Cipher = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			r.Cipher = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
		// case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		// 	r.Cipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
		// case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		// 	r.Cipher = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
		case tls.TLS_FALLBACK_SCSV:
			r.Cipher = "TLS_FALLBACK"
		default:
			log.Fatal("Unknown TLS cipher")
		}

		// when was the key first valid?
		r.DayValid = cert.NotBefore.String()
		r.Expires = cert.NotAfter.String()

		// when does the key expire?
		resultChan <- r
	}
}

// request worker to do stuff
func requestWorker(siteChan chan string, resultChan chan *SiteInfo, counter *int32) {
	client := &http.Client{
		CheckRedirect: allowRedirect,
	}

	for alive := true; alive; {
		select {
		case site := <-siteChan:
			//fmt.Printf("Fetching site %s\n", site)

			resp, err := client.Get("https://" + site)

			processInfo(site, resp, err, resultChan)
			_ = atomic.AddInt32(counter, 1)
			// default:
			// time.Sleep(time.Millisecond) // ugly hack
		}

		if atomic.LoadInt32(counter) == 500 {
			fmt.Println("goroutine done!")
			return
		}
	}
}

// create 16 worker threads for speed
func requestDispatch(siteChan chan string, resultChan chan *SiteInfo, counter *int32) {
	quit := make(chan bool)

	for i := 0; i < 16; i++ {
		go requestWorker(siteChan, resultChan, counter)
	}

	quit <- true
}

// function to write results to CVS file.
func saveResults(results chan *SiteInfo) {

	csvFile, err := os.Create("results.csv")
	if err != nil {
		log.Fatal("Results file already exists. Exiting...")
	}
	defer csvFile.Close()

	w := csv.NewWriter(csvFile)

	firstLine := []string{
		"Domain",
		"Encryption",
		"Day Valid",
		"Expires",
		"Cipher",
		// "Key Size",
		// "Valid CA",
	}

	err = w.Write(firstLine)

	if err != nil {
		log.Fatal("Couldn't write to CSV")
	}

	w.Flush()

	for count := 0; count < 500; count++ {
		result := <-results

		csvLine := []string{
			result.Domain,
			result.Encryption,
			result.DayValid,
			result.Expires,
			result.Cipher,
			// (string)(result.KeySize),
		}

		err = w.Write(csvLine)

		if err != nil {
			log.Fatal("Couldn't write line to results file: %#v\n", csvLine)
		}

		w.Flush()
	}
}

func main() {
	fmt.Println("Hello, world!")

	sites := make(chan string)
	go readSites(sites)

	results := make(chan *SiteInfo)
	counter := (int32)(1)
	go requestDispatch(sites, results, &counter)

	//for counter != 500 {
	//	time.Sleep(1 * time.Second)
	//}

	saveResults(results)
	fmt.Println("kthxbai")
}
