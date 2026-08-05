package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"ignotus/engine/internal/protocol"
	enginescanner "ignotus/engine/internal/scanner"
)

func main() {
	workers := flag.Int("workers", 20, "concurrent workers")
	rate := flag.Float64("rate", 10, "maximum jobs started per second")
	flag.Parse()
	if *workers < 1 || *workers > 128 || *rate <= 0 || *rate > 1000 {
		fmt.Fprintln(os.Stderr, "invalid workers or rate")
		os.Exit(2)
	}

	jobs := make(chan protocol.Request)
	results := make(chan protocol.Response)
	interval := time.Duration(float64(time.Second) / *rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	engine := enginescanner.Scanner{UserAgent: "IgnotusEngine/2.1"}
	var waitGroup sync.WaitGroup
	for range *workers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for job := range jobs {
				<-ticker.C
				results <- engine.Scan(context.Background(), job)
			}
		}()
	}

	go func() {
		waitGroup.Wait()
		close(results)
	}()

	go readJobs(jobs)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	for result := range results {
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func readJobs(jobs chan<- protocol.Request) {
	defer close(jobs)
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 64*1024), 1024*1024)
	for input.Scan() {
		var request protocol.Request
		if err := json.Unmarshal(input.Bytes(), &request); err != nil {
			continue
		}
		if request.Host == "" {
			continue
		}
		jobs <- request
	}
}
