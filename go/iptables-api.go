/*
 * Copyright (C) 2021	The Palner Group, Inc. (palner.com)
 *						Fred Posner (@fredposner)
 *
 * iptables-api is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * iptables-api is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gorilla/mux"
	"github.com/palner/pgrtools/pgparse"
)

var logFile string
var targetChain string
var APIport string

func init() {
	flag.StringVar(&targetChain, "target", "REJECT", "target chain for matching entries")
	flag.StringVar(&logFile, "log", "/var/log/iptables-api.log", "location of log file or - for stdout")
	flag.StringVar(&APIport, "port", "8082", "port to listen on")
}

func main() {
	// get flags
	flag.Parse()

	// Open our Log
	if logFile != "-" && logFile != "stdout" {
		lf, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			log.Panic(err)
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			runtime.Goexit()
		}
		defer lf.Close()

		log.SetOutput(lf)
	}

	log.Print("** Starting iptables-API")
	log.Print("** Choose to be optimistic, it feels better.")
	log.Print("** Licensed under GPLv2. See LICENSE for details.")
	log.Print("** API will listen on port ", APIport)

	router := mux.NewRouter()
	router.HandleFunc("/addip/{ipaddress}", addIPAddress).Methods("GET")
	router.HandleFunc("/blockip/{ipaddress}", addIPAddress).Methods("GET")
	router.HandleFunc("/flushchain", flushChain).Methods("GET")
	router.HandleFunc("/puship/{ipaddress}", pushIPAddress).Methods("GET")
	router.HandleFunc("/removeip/{ipaddress}", removeIPAddress).Methods("GET")
	router.HandleFunc("/unblockip/{ipaddress}", removeIPAddress).Methods("GET")
	router.HandleFunc("/", rAddIPAddress).Methods("POST")
	router.HandleFunc("/", rRemoveIPAddress).Methods("DELETE")
	http.ListenAndServe("0.0.0.0:"+APIport, router)
}

// Function to see if string within string
func contains(list []string, value string) bool {
	for _, val := range list {
		if val == value {
			return true
		}
	}
	return false
}

func checkIPAddress(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	} else {
		return true
	}
}

func checkIPAddressv4(ip string) (string, error) {
	if net.ParseIP(ip) == nil {
		return "", errors.New("Not an IP address")
	}
	for i := 0; i < len(ip); i++ {
		switch ip[i] {
		case '.':
			return "ipv4", nil
		case ':':
			return "ipv6", nil
		}
	}

	return "", errors.New("unknown error")
}

func initializeIPTables(ipt *iptables.IPTables) (string, error) {
	// Get existing chains from IPTABLES
	originaListChain, err := ipt.ListChains("filter")
	if err != nil {
		return "error", fmt.Errorf("failed to read iptables: %w", err)
	}

	// Search for INPUT in IPTABLES
	chain := "INPUT"
	if !contains(originaListChain, chain) {
		return "error", errors.New("iptables does not contain expected INPUT chain")
	}

	// Search for FORWARD in IPTABLES
	chain = "FORWARD"
	if !contains(originaListChain, chain) {
		return "error", errors.New("iptables does not contain expected FORWARD chain")
	}

	// Search for APIBAN in IPTABLES
	chain = "APIBANLOCAL"
	if contains(originaListChain, chain) {
		// APIBAN chain already exists
		return "chain exists", nil
	}

	log.Print("IPTABLES doesn't contain APIBANLOCAL. Creating now...")

	// Add APIBAN chain
	err = ipt.ClearChain("filter", chain)
	if err != nil {
		return "error", fmt.Errorf("failed to clear APIBANLOCAL chain: %w", err)
	}

	// Add APIBAN chain to INPUT
	err = ipt.Insert("filter", "INPUT", 1, "-j", chain)
	if err != nil {
		return "error", fmt.Errorf("failed to add APIBANLOCAL chain to INPUT chain: %w", err)
	}

	// Add APIBAN chain to FORWARD
	err = ipt.Insert("filter", "FORWARD", 1, "-j", chain)
	if err != nil {
		return "error", fmt.Errorf("failed to add APIBANLOCAL chain to FORWARD chain: %w", err)
	}

	return "chain created", nil
}

func iptableHandle(proto string, task string, ipvar string) (string, error) {
	log.Println("iptableHandle:", proto, task, ipvar)

	var ipProto iptables.Protocol
	switch proto {
	case "ipv6":
		ipProto = iptables.ProtocolIPv6
	default:
		ipProto = iptables.ProtocolIPv4
	}

	// Go connect for IPTABLES
	ipt, err := iptables.NewWithProtocol(ipProto)
	if err != nil {
		log.Println("iptableHandle:", err)
		return "", err
	}

	_, err = initializeIPTables(ipt)
	if err != nil {
		log.Fatalln("iptableHandler: failed to initialize IPTables:", err)
		return "", err
	}

	switch task {
	case "add":
		err = ipt.AppendUnique("filter", "APIBANLOCAL", "-s", ipvar, "-d", "0/0", "-j", targetChain)
		if err != nil {
			log.Println("iptableHandler: error adding address", err)
			return "", err
		} else {
			return "added", nil
		}
	case "delete":
		err = ipt.DeleteIfExists("filter", "APIBANLOCAL", "-s", ipvar, "-d", "0/0", "-j", targetChain)
		if err != nil {
			log.Println("iptableHandler: error removing address", err)
			return "", err
		} else {
			return "deleted", nil
		}
	case "flush":
		err = ipt.ClearChain("filter", "APIBANLOCAL")
		if err != nil {
			log.Println("iptableHandler:", proto, err)
			return "", err
		} else {
			return "flushed", nil
		}
	case "push":
		var exists = false
		exists, err = ipt.Exists("filter", "APIBANLOCAL", "-s", ipvar, "-d", "0/0", "-j", targetChain)
		if err != nil {
			log.Println("iptableHandler: error checking if ip already exists", err)
			return "error checking if ip already exists in the chain", err
		} else {
			if exists {
				err = errors.New("ip already exists")
				log.Println("iptableHandler: ip already exists", err)
				return "ip already exists", err
			} else {
				err = ipt.Insert("filter", "APIBANLOCAL", 1, "-s", ipvar, "-d", "0/0", "-j", targetChain)
				if err != nil {
					log.Println("iptableHandler: error pushing address", err)
					return "", err
				} else {
					return "pushed", nil
				}
			}
		}
	default:
		log.Println("iptableHandler: unknown task")
		return "", errors.New("unknown task")
	}
}

func pushIPAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	log.Println("processing pushIPAddress", params["ipaddress"])

	ipType, err := checkIPAddressv4(params["ipaddress"])
	if err != nil {
		log.Println(params["ipaddress"], "is not a valid ip address")
		http.Error(w, "{\"error\":\"only valid ip addresses supported\"}", http.StatusBadRequest)
		return
	}

	status, err := iptableHandle(ipType, "push", params["ipaddress"])
	if err != nil {
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
	} else {
		io.WriteString(w, "{\"success\":\""+status+"\"}\n")
	}
}

func addIPAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	log.Println("processing addIPAddress", params["ipaddress"])

	ipType, err := checkIPAddressv4(params["ipaddress"])
	if err != nil {
		log.Println(params["ipaddress"], "is not a valid ip address")
		http.Error(w, "{\"error\":\"only valid ip addresses supported\"}", http.StatusBadRequest)
		return
	}

	status, err := iptableHandle(ipType, "add", params["ipaddress"])
	if err != nil {
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
	} else {
		io.WriteString(w, "{\"success\":\""+status+"\"}\n")
	}
}

func removeIPAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	log.Println("processing removeIPAddress", params["ipaddress"])

	ipType, err := checkIPAddressv4(params["ipaddress"])
	if err != nil {
		log.Println(params["ipaddress"], "is not a valid ip address")
		http.Error(w, "{\"error\":\"only valid ip addresses supported\"}", http.StatusBadRequest)
		return
	}

	status, err := iptableHandle(ipType, "delete", params["ipaddress"])
	if err != nil {
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
	} else {
		io.WriteString(w, "{\"success\":\""+status+"\"}\n")
	}
}

func flushChain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	log.Println("processing flushChain")
	var flushResult string

	_, err := iptableHandle("ipv4", "flush", "")
	if err != nil {
		flushResult = "ipv4" + err.Error() + ". "
	} else {
		flushResult = "ipv4 flushed. "
	}

	_, err = iptableHandle("ipv6", "flush", "")
	if err != nil {
		flushResult = flushResult + "ipv6" + err.Error() + ". "
	} else {
		flushResult = flushResult + "ipv6 flushed. "
	}

	io.WriteString(w, "{\"result\":\""+flushResult+"\"}\n")
}

func rAddIPAddress(w http.ResponseWriter, r *http.Request) {
	log.Println("processing rAddIPAddress")

	// parse body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("bodyErr ", err.Error())
		http.Error(w, "{\"error\":\"unable to read body\"}", http.StatusBadRequest)
		return
	}

	log.Println("body received ->", string(body))
	keyVal := pgparse.ParseBody(body)
	keyVal = pgparse.LowerKeys(keyVal)
	log.Println("body (lowercase):", keyVal)

	// check for required fields
	requiredfields := []string{"ipaddress"}
	_, err = pgparse.CheckFields(keyVal, requiredfields)

	if err != nil {
		log.Println("errors occured:", err)
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
		return
	}

	ipType, err := checkIPAddressv4(keyVal["ipaddress"])
	if err != nil {
		log.Println(keyVal["ipaddress"], "is not a valid ip address")
		http.Error(w, "{\"error\":\"only valid ip addresses supported\"}", http.StatusBadRequest)
		return
	}

	status, err := iptableHandle(ipType, "add", keyVal["ipaddress"])
	if err != nil {
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
	} else {
		io.WriteString(w, "{\"success\":\""+status+"\"}\n")
	}
}

func rRemoveIPAddress(w http.ResponseWriter, r *http.Request) {
	log.Println("processing rRemoveIPAddress")

	// parse body
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("bodyErr ", err.Error())
		http.Error(w, "{\"error\":\"unable to read body\"}", http.StatusBadRequest)
		return
	}

	log.Println("body received ->", string(body))
	keyVal := pgparse.ParseBody(body)
	keyVal = pgparse.LowerKeys(keyVal)
	log.Println("body (lowercase):", keyVal)

	// check for required fields
	requiredfields := []string{"ipaddress"}
	_, err = pgparse.CheckFields(keyVal, requiredfields)

	if err != nil {
		log.Println("errors occured:", err)
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
		return
	}

	ipType, err := checkIPAddressv4(keyVal["ipaddress"])
	if err != nil {
		log.Println(keyVal["ipaddress"], "is not a valid ip address")
		http.Error(w, "{\"error\":\"only valid ip addresses supported\"}", http.StatusBadRequest)
		return
	}

	status, err := iptableHandle(ipType, "delete", keyVal["ipaddress"])
	if err != nil {
		http.Error(w, "{\"error\":\""+err.Error()+"\"}", http.StatusBadRequest)
	} else {
		io.WriteString(w, "{\"success\":\""+status+"\"}\n")
	}
}
