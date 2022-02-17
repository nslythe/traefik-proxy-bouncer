package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"gopkg.in/yaml.v2"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

type config struct {
	Key string `yaml:"crowdsec-key"`
	Url string `yaml:"crowdsec-url"`
}

func (c *config) getConfig() bool {
	yamlFile, err := ioutil.ReadFile("config.yaml")
	ok := true
	if err != nil {
		log.Printf("yaml error loading file : %v", err)
		ok = false
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("yaml error loading file : %v", err)
		ok = false
	}

	return ok
}

var bouncer csbouncer.LiveBouncer
var conf config
var listenAddress string

func init() {
	ok := conf.getConfig()
	if !ok {
		os.Exit(2)
	}
	listenAddress = "0.0.0.0:8090"

	bouncer = csbouncer.LiveBouncer{
		APIKey: conf.Key,
		APIUrl: conf.Url,
	}
	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}
}

func main() {
	log.Println("Started", listenAddress)
	http.HandleFunc("/auth", auth)
	http.ListenAndServe(listenAddress, nil)
}

func auth(response http.ResponseWriter, request *http.Request) {
	var source_ip string

	ip_value, prs := request.Header["Cf-Connecting-Ip"]
	if !prs {
		ip_value, prs = request.Header["X-Forwarded-For"]
		if !prs {
			ip_value, prs = request.Header["X-Real-Ip"]
			if !prs {
				ip_value = []string{
					strings.Split(request.RemoteAddr, ":")[0]}
			}
		}
	}

	source_ip = ip_value[0]

	decisions, err := bouncer.Get(source_ip)
	if err != nil {
		log.Fatalf("unable to get decision for ip '%s' : '%s'", source_ip, err)
	}
	if len(*decisions) == 0 {
		code := 200
		response.WriteHeader(code)
		fmt.Fprintf(response, "Ok\n")
	} else {
		code := 403
		response.WriteHeader(code)
		fmt.Fprintf(response, "Forbiden\n")
	}

	log.Println(source_ip)
}
