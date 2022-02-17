package main

	
import (
    "fmt"
	"log"
	"strings"
    "net/http"
	"gopkg.in/yaml.v2"
	"io/ioutil"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

type config struct {
    Key string `yaml:"crowdsec-key"`
    Url string `yaml:"crowdsec-url"`
	ListenAddress string `yaml:"ListenAddress"`
}
func (c *config) getConfig() *config {

    yamlFile, err := ioutil.ReadFile("config.yaml")
    if err != nil {
        log.Printf("yamlFile.Get err   #%v ", err)
    }
    err = yaml.Unmarshal(yamlFile, c)
    if err != nil {
        log.Fatalf("Unmarshal: %v", err)
    }

    return c
}

var bouncer csbouncer.LiveBouncer
var conf config

func init() {
	conf.getConfig()

	bouncer = csbouncer.LiveBouncer{
		APIKey:         conf.Key,
		APIUrl:         conf.Url,
	}
	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}
}

func main() {
    http.HandleFunc("/auth", auth)
	http.ListenAndServe(conf.ListenAddress, nil)
}

func auth(response http.ResponseWriter, request *http.Request){
	var source_ip string
	
	ip_value, prs := request.Header["Cf-Connecting-Ip"]
	if !prs {
		ip_value, prs = request.Header["X-Forwarded-For"]
		if !prs {
			ip_value, prs = request.Header["X-Real-Ip"]
			if (!prs){
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
	if len(*decisions) == 0{
		code := 200
		response.WriteHeader(code)
		fmt.Fprintf(response, "Ok\n")
		}else{
		code := 403
		response.WriteHeader(code)
		fmt.Fprintf(response, "Forbiden\n")
	}
	
	log.Println(source_ip)
	//log.Println(request.Header)
}