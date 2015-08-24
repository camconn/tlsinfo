package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

var DOMAIN_LIST = "sites.txt"

type SiteInfo struct {
	Domain     string
	Encryption string // "" = None; "TLSv1.2", etc.
	DayValid   string // first day key is valid
	Expires    string // When key expires
	Cipher     string // cipher suite being used
	KeySize    int
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
		resultChan <- r
	}
}

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
		default:
			time.Sleep(time.Millisecond) // ugly hack
		}

		if atomic.LoadInt32(counter) == 500 {
			fmt.Println("goroutine done!")
			return
		}
	}
}

func requestDispatch(siteChan chan string, resultChan chan *SiteInfo, counter *int32) {
	quit := make(chan bool)

	for i := 0; i < 16; i++ {
		go requestWorker(siteChan, resultChan, counter)
	}

	quit <- true
}

func saveResults(results chan *SiteInfo) {

	csvFile, err := os.Create("results.txt")
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
		"Key Size",
		"Valid CA",
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
			(string)(result.KeySize),
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
