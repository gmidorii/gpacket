package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"

	"github.com/google/gopacket/pcap"
)

var (
	device       string        = "en0"
	snapshot_len int32         = 1024
	timeout      time.Duration = 30 * time.Second
)

func main() {
	handle, err := pcap.OpenLive(device, snapshot_len, false, timeout)
	if err != nil {
		log.Fatalln(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("tcp and port 80")
	if err != nil {
		log.Fatal(err)
	}
	packet := gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range packet.Packets() {
		fmt.Println(p)
	}
}

func findDevices() {
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
