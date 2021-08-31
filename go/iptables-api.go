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
	"log"
	"net"
	"net/http"
	"os"
	"runtime"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gorilla/mux"
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
	router.HandleFunc("/removeip/{ipaddress}", removeIPAddress).Methods("GET")
	router.HandleFunc("/flushchain", flushChain).Methods("GET")
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

func checkIPAddressv4(ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	}
	for i := 0; i < len(ip); i++ {
		switch ip[i] {
		case '.':
			return true
		case ':':
			return false
		}
	}

	return false
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

func addIPAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	log.Println("processing addIPAddress", params["ipaddress"])

	if checkIPAddressv4(params["ipaddress"]) {
		log.Println(params["ipaddress"], "is a valid ip address")
	} else {
		log.Println(params["ipaddress"], "is not a valid ipv4 address")
		http.Error(w, "{\"error\":\"only valid ipv4 address supported\"}", http.StatusBadRequest)
		return
	}

	// Go connect for IPTABLES
	ipt, err := iptables.New()
	if err != nil {
		log.Println(err)
		http.Error(w, "{\"error\":\"error with iptables\"}", http.StatusInternalServerError)
	}

	_, err = initializeIPTables(ipt)
	if err != nil {
		log.Fatalln("failed to initialize IPTables:", err)
		http.Error(w, "{\"error\":\"error initializing iptables\"}", http.StatusInternalServerError)
	}

	err = ipt.AppendUnique("filter", "APIBANLOCAL", "-s", params["ipaddress"], "-d", "0/0", "-j", targetChain)
	if err != nil {
		log.Println("error adding address", err)
		http.Error(w, "{\"error\":\"error adding address\"}", http.StatusBadRequest)
		return
	}

	io.WriteString(w, "{\"success\":\"added\"}\n")
}

func removeIPAddress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	log.Println("processing removeIPAddress", params["ipaddress"])

	if checkIPAddressv4(params["ipaddress"]) {
		log.Println(params["ipaddress"], "is a valid ip address")
	} else {
		log.Println(params["ipaddress"], "is not a valid ipv4 address")
		http.Error(w, "{\"error\":\"only valid ipv4 address supported\"}", http.StatusBadRequest)
		return
	}

	// Go connect for IPTABLES
	ipt, err := iptables.New()
	if err != nil {
		log.Println(err)
		http.Error(w, "{\"error\":\"error with iptables\"}", http.StatusInternalServerError)
	}

	_, err = initializeIPTables(ipt)
	if err != nil {
		log.Fatalln("failed to initialize IPTables:", err)
		http.Error(w, "{\"error\":\"error initializing iptables\"}", http.StatusInternalServerError)
	}

	err = ipt.DeleteIfExists("filter", "APIBANLOCAL", "-s", params["ipaddress"], "-d", "0/0", "-j", targetChain)
	if err != nil {
		log.Println("error removing address", err)
		http.Error(w, "{\"error\":\"error removing address\"}", http.StatusBadRequest)
		return
	}

	io.WriteString(w, "{\"success\":\"removed\"}\n")
}

func flushChain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	log.Println("processing flushChain")

	// Go connect for IPTABLES
	ipt, err := iptables.New()
	if err != nil {
		log.Println(err)
		http.Error(w, "{\"error\":\"error with iptables\"}", http.StatusInternalServerError)
	}

	_, err = initializeIPTables(ipt)
	if err != nil {
		log.Fatalln("failed to initialize IPTables:", err)
		http.Error(w, "{\"error\":\"error initializing iptables\"}", http.StatusInternalServerError)
	}

	err = ipt.ClearChain("filter", "APIBANLOCAL")
	if err != nil {
		log.Print("Flushing APIBANLOCAL chain failed. ", err.Error())
		http.Error(w, "{\"error\":\"error flushing chain\"}", http.StatusBadRequest)
	} else {
		log.Print("APIBANLOCAL chain flushed.")
		io.WriteString(w, "{\"success\":\"flushed\"}\n")
	}
}
