package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type HostInfo struct{
	DomainName string
	IP []string
}

func main(){
	interval := 5
	port := 2931

	go monitor(port)
	broadcastLocalInfo(interval, port)
}

//监听局域网内其他电脑发送的消息
func monitor(port int){
	listen, er := net.ListenUDP("udp", &net.UDPAddr{
		IP: net.IPv4(0, 0, 0, 0),
		Port: port,
	})
	if er != nil{
		panic(er)
	}
	defer listen.Close()

	for{
		data := make([]byte, 1024)

		size, addr, err := listen.ReadFromUDP(data)
		if err != nil{
			fmt.Println("获取消息失败:", err.Error())
			continue
		}
		localInfo := getLocalInfo()
		isLocal := false
		for _, value := range localInfo.IP{
			if addr.IP.String() == value{ //本机
				isLocal = true
				break
			}
		}
		if isLocal{
			continue
		}
		str := data[:size]

		var info HostInfo
		err = json.Unmarshal(str, &info)
		if err != nil{
			fmt.Println("收到未知数据:", string(str))
			continue
		}

		modifyHosts(info.DomainName + ".ws01.fun", addr.IP.String())
	}
}

//修改系统hosts文件
func modifyHosts(hostName, serverIP string){
	osType := runtime.GOOS

	var hostsPath string
	if osType == "windows"{
		hostsPath = "C:\\WINDOWS\\system32\\drivers\\etc\\hosts"
	}else{
		hostsPath = "/etc/hosts"
	}

	data, er := os.ReadFile(hostsPath)
	if er != nil{
		fmt.Println(er)
		return
	}
	str := string(data)
	list := strings.Split(str, "\n")
	isOK := false
	var buffer string
	for index, value := range list{
		re_leadclose_whtsp := regexp.MustCompile(`^[\s\p{Zs}]+|[\s\p{Zs}]+$`)
		re_inside_whtsp := regexp.MustCompile(`[\s\p{Zs}]{2,}`)
		final := re_leadclose_whtsp.ReplaceAllString(value, "")
		final = re_inside_whtsp.ReplaceAllString(final, " ")
		final = strings.Replace(final, "\t", " ", 1)

		if final == "" {
			if index + 1 < len(list) {
				buffer += "\n"
			}
		}else if final[:1] == "#"{ //过滤注释
			buffer += final + "\n"
		}else if strings.Index(final, "::") != -1{ //过滤ipv6
			buffer += final + "\n"
		}else{
			ip := final[:strings.Index(final, " ")]
			name := final[strings.Index(final, " ")+1:]
			if name == hostName && ip == serverIP{
				return
			}else if name == hostName{
				buffer += serverIP + " " + name + "\n"
				isOK = true
				break
			}else{
				buffer += final + "\n"
			}
		}
	}
	file, er := os.Create(hostsPath)
	if er != nil{
		fmt.Println(er)
		return
	}
	defer file.Close()
	file.Write([]byte(buffer))
	if !isOK{
		file.Write([]byte(serverIP + " " + hostName + "\n"))
	}
}

//获取本机信息
func getLocalInfo()*HostInfo{
	info := &HostInfo{}
	info.IP = make([]string, 1)
	var err error
	info.DomainName, err = os.Hostname()
	if err != nil{
		return nil
	}

	addrList, er := net.InterfaceAddrs()
	if er != nil{
		fmt.Println("获取本机ip失败，原因:", er.Error())
		return nil
	}

	for _, addr := range addrList{
		if ip, ok := addr.(*net.IPNet); ok && !ip.IP.IsLoopback(){
			if ip.IP.To4() != nil{
				info.IP = append(info.IP, ip.IP.String())
			}
		}
	}

	return info
}

//定时广播自身ip与域名
func broadcastLocalInfo(interval, serverPort int){
	ticker := time.NewTicker(time.Minute * time.Duration(interval))

	sendData(serverPort) //刚启动时发送一遍

	for {
		select {
		case <-ticker.C:
			sendData(serverPort)
		}
	}
}

//发送消息
func sendData(serverPort int){
	conn, er := net.DialUDP("udp", &net.UDPAddr{
		IP: net.IPv4(0, 0, 0, 0),
	}, &net.UDPAddr{
		IP: net.IPv4(255, 255, 255, 255),
		Port: serverPort,
	})
	if er != nil{
		fmt.Println(er)
		return
	}

	info := HostInfo{}
	info.DomainName, _ = os.Hostname()
	data, err := json.Marshal(info)
	if err != nil{
		fmt.Println(err)
		conn.Close()
		return
	}
	conn.Write(data);
	conn.Close()
}
