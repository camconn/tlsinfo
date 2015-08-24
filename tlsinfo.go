package main

import (
	"fmt"
	// "crypto/tls"
	// "net/http"
	"bufio"
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
	ValidCA    bool // does key use valid CA?

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

func requestWorker(siteChan chan string, resultChan chan SiteInfo, counter *int32) {
	alive := true
	for alive {
		select {
		case site := <-siteChan:
			fmt.Printf("Fetching site %s\n", site)
			_ = atomic.AddInt32(counter, 1)
		default:
			time.Sleep(time.Millisecond)
		}

		if atomic.LoadInt32(counter) == 500 {
			fmt.Println("goroutine done!")
			return
		} // else {
		// time.Sleep(time.Second)
		// }

	}
}

func requestDispatch(siteChan chan string, resultChan chan SiteInfo, counter *int32) {
	quit := make(chan bool)

	for i := 0; i < 8; i++ {
		go requestWorker(siteChan, resultChan, counter)
	}

	quit <- true
}

func main() {
	fmt.Println("Hello, world!")

	sites := make(chan string)
	go readSites(sites)

	results := make(chan SiteInfo)
	counter := (int32)(1)
	go requestDispatch(sites, results, &counter)

	for counter != 500 {
		time.Sleep(1 * time.Second)
	}

	fmt.Println("kthxbai")
	// saveResults(results)
}
