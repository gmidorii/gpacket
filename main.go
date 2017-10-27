package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalln(err)
	}
	for _, device := range devices {
		fmt.Println("Name: ", device.Name)
		fmt.Println("Description: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("IP: ", address.IP)
			fmt.Println("Netmask: ", address.Netmask)
		}
	}
}
