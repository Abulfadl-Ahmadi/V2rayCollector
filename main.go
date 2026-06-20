package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/jszwec/csvutil"
	"github.com/mrvcoder/V2rayCollector/collector"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	client      = &http.Client{}
	maxMessages = 50

	// uniqueConfigs uses a map of [protocol] -> [raw config] -> [channelName]
	// This structure guarantees deduplication while remembering the source channel.
	uniqueConfigsMu sync.Mutex
	uniqueConfigs   = map[string]map[string]string{
		"ss":     make(map[string]string),
		"vmess":  make(map[string]string),
		"trojan": make(map[string]string),
		"vless":  make(map[string]string),
		"mixed":  make(map[string]string),
	}

	// The regex handles matching until a #, %3A%40 (encoded), or end of string ($)
	myregex = map[string]string{
		"ss":     `(?m)(...ss:|^ss:)\/\/.+?(?:%3A%40|#|$)`,
		"vmess":  `(?m)vmess:\/\/.+`,
		"trojan": `(?m)trojan:\/\/.+?(?:%3A%40|#|$)`,
		"vless":  `(?m)vless:\/\/.+?(?:%3A%40|#|$)`,
	}
	sortFlag = flag.Bool("sort", false, "sort from latest to oldest (default : false)")
)

type ChannelsType struct {
	URL             string `csv:"URL"`
	AllMessagesFlag bool   `csv:"AllMessagesFlag"`
}

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()

	fileData, err := collector.ReadFileContent("channels.csv")
	if err != nil {
		gologger.Fatal().Msg("error: " + err.Error())
	}

	var channels []ChannelsType
	if err = csvutil.Unmarshal([]byte(fileData), &channels); err != nil {
		gologger.Fatal().Msg("error: " + err.Error())
	}

	var wg sync.WaitGroup
	// Limit maximum concurrency to 5 routines
	concurrencyLimit := 5
	sem := make(chan struct{}, concurrencyLimit)

	for _, channel := range channels {
		wg.Add(1)
		sem <- struct{}{} // acquire token

		go func(c ChannelsType) {
			defer wg.Done()
			defer func() { <-sem }() // release token

			c.URL = collector.ChangeUrlToTelegramWebUrl(c.URL)
			channelName := extractChannelName(c.URL)

			resp := HttpRequest(c.URL)
			if resp == nil {
				return
			}
			
			doc, err := goquery.NewDocumentFromReader(resp.Body)
			resp.Body.Close()
			if err != nil {
				gologger.Error().Msg(err.Error())
				return
			}

			fmt.Println("\n---------------------------------------")
			gologger.Info().Msg("Crawling " + c.URL)
			CrawlForV2ray(doc, c.URL, c.AllMessagesFlag, channelName)
			gologger.Info().Msg("Crawled " + c.URL + " ! ")
			fmt.Println("---------------------------------------\n")
		}(channel)
	}

	// Wait for all worker threads to finish executing
	wg.Wait()

	generateOutputFiles()
}

func extractChannelName(urlStr string) string {
	urlStr = strings.TrimSuffix(urlStr, "/")
	parts := strings.Split(urlStr, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return "unknown"
}

func addExtractedConfig(proto, rawConfig, channelName string) {
	rawConfig = strings.TrimSpace(rawConfig)
	if rawConfig == "" {
		return
	}

	// Strip out any existing suffix tags so we have the pure URI string
	rawConfig = strings.TrimSuffix(rawConfig, "#")
	rawConfig = strings.TrimSuffix(rawConfig, "%3A%40")

	uniqueConfigsMu.Lock()
	defer uniqueConfigsMu.Unlock()

	// Deduping step: Will only write if this raw config has not been captured globally yet
	if _, exists := uniqueConfigs[proto][rawConfig]; !exists {
		uniqueConfigs[proto][rawConfig] = channelName
	}
}

func CrawlForV2ray(doc *goquery.Document, channelLink string, HasAllMessagesFlag bool, channelName string) {
	messages := doc.Find(".tgme_widget_message_wrap").Length()
	link, exist := doc.Find(".tgme_widget_message_wrap .js-widget_message").Last().Attr("data-post")

	if messages < maxMessages && exist {
		number := strings.Split(link, "/")[1]
		doc = GetMessages(maxMessages, doc, number, channelLink)
	}

	if HasAllMessagesFlag {
		doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
			messageText, _ := s.Html()
			str := strings.Replace(messageText, "<br/>", "\n", -1)
			docHtml, _ := goquery.NewDocumentFromReader(strings.NewReader(str))
			messageText = docHtml.Text()
			lines := strings.Split(strings.TrimSpace(messageText), "\n")
			for _, data := range lines {
				extractedConfigs := strings.Split(ExtractConfig(data, []string{}), "\n")
				for _, extractedConfig := range extractedConfigs {
					extractedConfig = strings.ReplaceAll(extractedConfig, " ", "")
					if extractedConfig != "" {
						re := regexp.MustCompile(myregex["vmess"])
						matches := re.FindStringSubmatch(extractedConfig)

						if len(matches) > 0 {
							// For vmess configs, wipe out PS placeholder during the extraction step
							extractedConfig = EditVmessPs(extractedConfig, false, "")
						}
						
						if extractedConfig != "" {
							addExtractedConfig("mixed", extractedConfig, channelName)
						}
					}
				}
			}
		})
	} else {
		doc.Find("code,pre").Each(func(j int, s *goquery.Selection) {
			messageText, _ := s.Html()
			str := strings.ReplaceAll(messageText, "<br/>", "\n")
			docHtml, _ := goquery.NewDocumentFromReader(strings.NewReader(str))
			messageText = docHtml.Text()
			lines := strings.Split(strings.TrimSpace(messageText), "\n")
			for _, data := range lines {
				extractedConfigs := strings.Split(ExtractConfig(data, []string{}), "\n")
				for protoRegex, regexValue := range myregex {
					for _, extractedConfig := range extractedConfigs {
						re := regexp.MustCompile(regexValue)
						matches := re.FindStringSubmatch(extractedConfig)
						if len(matches) > 0 {
							extractedConfig = strings.ReplaceAll(extractedConfig, " ", "")
							if extractedConfig != "" {
								if protoRegex == "vmess" {
									extractedConfig = EditVmessPs(extractedConfig, false, "")
								} else if protoRegex == "ss" {
									Prefix := strings.Split(matches[0], "ss://")[0]
									if Prefix != "" {
										continue
									}
								}
								
								if extractedConfig != "" {
									addExtractedConfig(protoRegex, extractedConfig, channelName)
								}
							}
						}
					}
				}
			}
		})
	}
}

func ExtractConfig(Txt string, Tempconfigs []string) string {
	for protoRegex, regexValue := range myregex {
		re := regexp.MustCompile(regexValue)
		matches := re.FindStringSubmatch(Txt)
		extractedConfig := ""
		if len(matches) > 0 {
			if protoRegex == "ss" {
				Prefix := strings.Split(matches[0], "ss://")[0]
				if Prefix == "" {
					extractedConfig = "\n" + matches[0]
				} else if Prefix != "vle" {
					d := strings.Split(matches[0], "ss://")
					extractedConfig = "\n" + "ss://" + d[1]
				}
			} else {
				extractedConfig = "\n" + matches[0]
			}

			Tempconfigs = append(Tempconfigs, extractedConfig)
			Txt = strings.ReplaceAll(Txt, matches[0], "")
			// Fix: Corrected recursive return issue
			return ExtractConfig(Txt, Tempconfigs)
		}
	}
	return strings.Join(Tempconfigs, "\n")
}

func EditVmessPs(config string, addName bool, newName string) string {
	if config == "" {
		return ""
	}
	slice := strings.Split(config, "vmess://")
	if len(slice) > 1 {
		decodedBytes, err := base64.StdEncoding.DecodeString(slice[1])
		if err == nil {
			var data map[string]interface{}
			err = json.Unmarshal(decodedBytes, &data)
			if err == nil {
				if addName {
					data["ps"] = newName
				} else {
					data["ps"] = ""
				}

				jsonData, _ := json.Marshal(data)
				base64Encoded := base64.StdEncoding.EncodeToString(jsonData)
				return "vmess://" + base64Encoded
			}
		}
	}
	// return original payload if standard parsing fails
	return config
}

func generateOutputFiles() {
	gologger.Info().Msg("Creating output files !")

	// Keep an isolated count sequence mapped to individual channel sources
	channelCounters := make(map[string]int)

	for proto, configMap := range uniqueConfigs {
		var linesArr []string

		for rawConfig, channelName := range configMap {
			channelCounters[channelName]++
			counter := channelCounters[channelName]
			// Generates dynamic ID: e.g. "v2ray_configs - 1"
			newName := fmt.Sprintf("%s - %d", channelName, counter)

			finalConfig := applyConfigName(proto, rawConfig, newName)
			if finalConfig != "" {
				linesArr = append(linesArr, finalConfig)
			}
		}

		if *sortFlag {
			linesArr = collector.Reverse(linesArr)
		} else {
			linesArr = collector.Reverse(linesArr)
			linesArr = collector.Reverse(linesArr)
		}

		lines := strings.Join(linesArr, "\n")
		lines = strings.TrimSpace(lines)
		if lines != "" {
			collector.WriteToFile(lines, proto+"_iran.txt")
		}
	}

	gologger.Info().Msg("All Done :D")
}

func applyConfigName(proto, rawConfig, newName string) string {
	if proto == "vmess" || strings.HasPrefix(rawConfig, "vmess://") {
		return EditVmessPs(rawConfig, true, newName)
	}
	// Append # trailing name for trojan, ss, vless and general mixed
	return rawConfig + "#" + newName
}

func loadMore(link string) *goquery.Document {
	req, _ := http.NewRequest("GET", link, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	doc, _ := goquery.NewDocumentFromReader(resp.Body)
	return doc
}

func HttpRequest(url string) *http.Response {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		gologger.Error().Msg(fmt.Sprintf("Error When requesting to: %s Error : %s", url, err))
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		gologger.Error().Msg(err.Error())
		return nil
	}
	return resp
}

func GetMessages(length int, doc *goquery.Document, number string, channel string) *goquery.Document {
	x := loadMore(channel + "?before=" + number)
	if x == nil {
		return doc
	}

	html2, _ := x.Html()
	reader2 := strings.NewReader(html2)
	doc2, _ := goquery.NewDocumentFromReader(reader2)

	doc.Find("body").AppendSelection(doc2.Find("body").Children())
	newDoc := goquery.NewDocumentFromNode(doc.Selection.Nodes[0])
	messages := newDoc.Find(".js-widget_message_wrap").Length()

	if messages > length {
		return newDoc
	} else {
		num, _ := strconv.Atoi(number)
		n := num - 21
		if n > 0 {
			ns := strconv.Itoa(n)
			// Fix: Corrected recursive scope return for infinite loops issue
			return GetMessages(length, newDoc, ns, channel)
		} else {
			return newDoc
		}
	}
}
