package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/jszwec/csvutil"
	"github.com/mrvcoder/V2rayCollector/collector"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	client      = &http.Client{Timeout: 10 * time.Second}
	maxMessages = 50
	configs     = map[string]string{
		"ss":     "",
		"vmess":  "",
		"trojan": "",
		"vless":  "",
		"mixed":  "",
	}
	configsMutex sync.Mutex

	// Updated regex: case‑insensitive, allow leading/trailing whitespace, and capture full URI.
	myregex = map[string]string{
		"ss":     `(?i)(?m)(?:\s*)(?:ss:\/\/[A-Za-z0-9+/\-_=]+@[A-Za-z0-9.\-]+:\d+)(?:\s*)(?:#|\s|$)`,
		"vmess":  `(?i)(?m)(?:\s*)vmess:\/\/[A-Za-z0-9+/\-_=]+(?:\s*)`,
		"trojan": `(?i)(?m)(?:\s*)trojan:\/\/[A-Za-z0-9+/\-_=]+@[A-Za-z0-9.\-]+:\d+\?(?:[^\s#]+)(?:#|\s|$)`,
		"vless":  `(?i)(?m)(?:\s*)vless:\/\/[A-Za-z0-9+/\-_=]+@[A-Za-z0-9.\-]+:\d+\?(?:[^\s#]+)(?:#|\s|$)`,
	}

	sort = flag.Bool("sort", false, "sort from latest to oldest (default: false)")
)

// ChannelsType represents a channel entry from the CSV.
type ChannelsType struct {
	URL             string `csv:"URL"`
	AllMessagesFlag bool   `csv:"AllMessagesFlag"`
}

// perChannelCounters holds the counters for each protocol for a single channel.
type perChannelCounters struct {
	ss     int32
	vmess  int32
	trojan int32
	vless  int32
	mixed  int32
}

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()

	fileData, err := collector.ReadFileContent("channels.csv")
	if err != nil {
		gologger.Fatal().Msgf("failed to read channels.csv: %v", err)
	}
	var channels []ChannelsType
	if err = csvutil.Unmarshal([]byte(fileData), &channels); err != nil {
		gologger.Fatal().Msgf("failed to parse CSV: %v", err)
	}

	// Worker pool: process up to 5 channels concurrently.
	const maxWorkers = 5
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup

	for _, ch := range channels {
		wg.Add(1)
		go func(ch ChannelsType) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			// Normalize URL to Telegram web format.
			ch.URL = collector.ChangeUrlToTelegramWebUrl(ch.URL)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			resp, err := httpRequestWithContext(ctx, ch.URL)
			if err != nil {
				gologger.Error().Msgf("request failed for %s: %v", ch.URL, err)
				return
			}
			defer resp.Body.Close()

			doc, err := goquery.NewDocumentFromReader(resp.Body)
			if err != nil {
				gologger.Error().Msgf("failed to parse HTML for %s: %v", ch.URL, err)
				return
			}

			gologger.Info().Msgf("Crawling %s", ch.URL)

			// Process this channel with its own counters.
			counters := &perChannelCounters{}
			crawlForV2ray(doc, ch.URL, ch.AllMessagesFlag, counters)

			gologger.Info().Msgf("Crawled %s", ch.URL)
		}(ch)
	}

	wg.Wait()
	gologger.Info().Msg("All channels processed, writing output files")

	// Write final files with deduplication and optional sorting.
	for proto, content := range configs {
		lines := collector.RemoveDuplicate(content)
		if *sort {
			// Newest first: split, reverse, join.
			parts := strings.Split(lines, "\n")
			parts = collector.Reverse(parts)
			lines = strings.Join(parts, "\n")
		} else {
			// Oldest first: reverse twice (no change) but we keep it explicit.
			parts := strings.Split(lines, "\n")
			parts = collector.Reverse(parts)
			parts = collector.Reverse(parts)
			lines = strings.Join(parts, "\n")
		}
		lines = strings.TrimSpace(lines)
		if lines != "" {
			collector.WriteToFile(lines, proto+"_iran.txt")
		}
	}

	gologger.Info().Msg("All Done")
}

// httpRequestWithContext performs a GET request with context.
func httpRequestWithContext(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

// extractChannelName extracts the channel name from a Telegram web URL.
func extractChannelName(link string) string {
	re := regexp.MustCompile(`t\.me/([^/?]+)`)
	matches := re.FindStringSubmatch(link)
	if len(matches) > 1 {
		return matches[1]
	}
	return "unknown"
}

// editVmessPs decodes a vmess link, sets the "ps" field with channel name and counter, and re‑encodes.
func editVmessPs(config string, channelName string, counter *int32) string {
	if config == "" {
		return ""
	}
	parts := strings.Split(config, "vmess://")
	if len(parts) != 2 {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var data map[string]interface{}
	if err := json.Unmarshal(decoded, &data); err != nil {
		return ""
	}
	*counter++
	data["ps"] = fmt.Sprintf("%s - %d", channelName, *counter)
	jsonData, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	encoded := base64.StdEncoding.EncodeToString(jsonData)
	return "vmess://" + encoded
}

// crawlForV2ray extracts configs from the document, using channel‑specific counters for naming.
func crawlForV2ray(doc *goquery.Document, channelLink string, allMessages bool, counters *perChannelCounters) {
	channelName := extractChannelName(channelLink)

	// Load more messages if needed.
	msgWraps := doc.Find(".tgme_widget_message_wrap")
	messages := msgWraps.Length()
	lastPost, exists := msgWraps.Last().Find(".js-widget_message").Attr("data-post")

	if messages < maxMessages && exists {
		number := strings.Split(lastPost, "/")[1]
		doc = getMoreMessages(maxMessages, doc, number, channelLink)
	}

	// Helper to add a config to the global map with proper naming.
	addConfig := func(proto, rawConfig string) {
		if rawConfig == "" {
			return
		}
		var named string
		switch proto {
		case "vmess":
			var ctr *int32
			switch proto {
			case "vmess":
				ctr = &counters.vmess
			default: // should not happen
				ctr = &counters.mixed
			}
			named = editVmessPs(rawConfig, channelName, ctr)
			if named == "" {
				return
			}
		default:
			// For ss, trojan, vless, append a comment.
			var ctr *int32
			switch proto {
			case "ss":
				ctr = &counters.ss
			case "trojan":
				ctr = &counters.trojan
			case "vless":
				ctr = &counters.vless
			default:
				ctr = &counters.mixed
			}
			*ctr++
			named = fmt.Sprintf("%s #%s - %d", rawConfig, channelName, *ctr)
		}

		configsMutex.Lock()
		configs[proto] += named + "\n"
		configsMutex.Unlock()
	}

	// Extracting configs from the document.
	if allMessages {
		doc.Find(".tgme_widget_message_text").Each(func(_ int, s *goquery.Selection) {
			html, _ := s.Html()
			text := strings.ReplaceAll(html, "<br/>", "\n")
			subDoc, _ := goquery.NewDocumentFromReader(strings.NewReader(text))
			msgText := subDoc.Text()
			lines := strings.Split(msgText, "\n")
			for _, line := range lines {
				extracted := extractConfigs(line)
				for _, raw := range extracted {
					// Determine protocol by matching regex.
					for proto, reStr := range myregex {
						if matched, _ := regexp.MatchString(reStr, raw); matched {
							if proto == "vmess" {
								// For mixed we still treat as vmess with its own counter.
								addConfig("mixed", raw)
							} else {
								addConfig("mixed", raw)
							}
							break
						}
					}
				}
			}
		})
	} else {
		// Only code and pre tags.
		doc.Find("code, pre").Each(func(_ int, s *goquery.Selection) {
			html, _ := s.Html()
			text := strings.ReplaceAll(html, "<br/>", "\n")
			subDoc, _ := goquery.NewDocumentFromReader(strings.NewReader(text))
			msgText := subDoc.Text()
			lines := strings.Split(msgText, "\n")
			for _, line := range lines {
				extracted := extractConfigs(line)
				for _, raw := range extracted {
					for proto, reStr := range myregex {
						if matched, _ := regexp.MatchString(reStr, raw); matched {
							addConfig(proto, raw)
							break
						}
					}
				}
			}
		})
	}
}

// extractConfigs finds all configuration strings in a text using the global regex list.
func extractConfigs(text string) []string {
	var found []string
	for _, reStr := range myregex {
		re := regexp.MustCompile(reStr)
		matches := re.FindAllString(text, -1)
		for _, m := range matches {
			m = strings.TrimSpace(m)
			if m != "" {
				found = append(found, m)
			}
		}
	}
	return found
}

// getMoreMessages recursively loads older messages until we have at least maxMessages.
func getMoreMessages(limit int, doc *goquery.Document, before string, channel string) *goquery.Document {
	url := channel + "?before=" + before
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		gologger.Error().Msgf("failed to load more messages: %v", err)
		return doc
	}
	defer resp.Body.Close()

	newDoc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		gologger.Error().Msgf("failed to parse more messages: %v", err)
		return doc
	}

	// Append new nodes to existing doc.
	doc.Find("body").AppendSelection(newDoc.Find("body").Children())
	merged := goquery.NewDocumentFromNode(doc.Selection.Nodes[0])

	count := merged.Find(".js-widget_message_wrap").Length()
	if count >= limit {
		return merged
	}

	// Find last post id from the newly added messages.
	last := merged.Find(".js-widget_message_wrap").Last().Find(".js-widget_message")
	post, exists := last.Attr("data-post")
	if !exists {
		return merged
	}
	numStr := strings.Split(post, "/")[1]
	num, _ := strconv.Atoi(numStr)
	if num <= 21 {
		return merged
	}
	return getMoreMessages(limit, merged, strconv.Itoa(num-21), channel)
}
