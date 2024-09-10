package task

import (
	"bufio"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/peanut996/CloudflareWarpSpeedTest/i18n"
)

var (
	IPText string
	IPFile string
)

func isIPv4(ip string) bool {
	return strings.Contains(ip, ".")
}

func randIPEndWith(num byte) byte {
	if num == 0 { // 对于 /32 这种单独的 IP
		return byte(0)
	}
	return byte(rand.IntN(int(num)))
}

type IPRanges struct {
	ips     []*net.IPAddr
	mask    string
	firstIP net.IP
	ipNet   *net.IPNet
}

func newIPRanges() *IPRanges {
	return &IPRanges{
		ips: make([]*net.IPAddr, 0),
	}
}

func (r *IPRanges) fixIP(ip string) string {
	if i := strings.IndexByte(ip, '/'); i < 0 {
		if isIPv4(ip) {
			r.mask = "/32"
		} else {
			r.mask = "/128"
		}
		ip += r.mask
	} else {
		r.mask = ip[i:]
	}
	return ip
}

func (r *IPRanges) parseCIDR(ip string) {
	var err error
	if r.firstIP, r.ipNet, err = net.ParseCIDR(r.fixIP(ip)); err != nil {
		log.Fatalln(i18n.QueryI18n(i18n.CidrInvalid), err)
	}
}

func (r *IPRanges) appendIPv4(d byte) {
	r.appendIP(net.IPv4(r.firstIP[12], r.firstIP[13], r.firstIP[14], d))
}

func (r *IPRanges) appendIP(ip net.IP) {
	r.ips = append(r.ips, &net.IPAddr{IP: ip})
}

func (r *IPRanges) getIPRange() (minIP, hosts byte) {
	minIP = r.firstIP[15] & r.ipNet.Mask[3]

	m := net.IPv4Mask(255, 255, 255, 255)
	for i, v := range r.ipNet.Mask {
		m[i] ^= v
	}
	total, _ := strconv.ParseInt(m.String(), 16, 32)
	if total > 255 {
		hosts = 255
		return
	}
	hosts = byte(total)
	return
}

func (r *IPRanges) chooseIPv4() {
	if r.mask == "/32" {
		r.appendIP(r.firstIP)
	} else {
		minIP, hosts := r.getIPRange()
		for r.ipNet.Contains(r.firstIP) {
			for i := 0; i <= int(hosts); i++ {
				r.appendIPv4(byte(i) + minIP)
			}
			r.firstIP[14]++
			if r.firstIP[14] == 0 {
				r.firstIP[13]++
				if r.firstIP[13] == 0 {
					r.firstIP[12]++
				}
			}
		}
	}
}

func (r *IPRanges) chooseIPv6() {
	maskSize, _ := r.ipNet.Mask.Size()

	if maskSize == 128 {
		r.appendIP(r.firstIP)
	} else {
		if maskSize == 120 {
			// 对于 /120，我们可以在最后的8位进行迭代
			for i := uint16(0); i <= 0xFF; i++ {
				r.firstIP[15] = byte(i & 0xFF)
				targetIP := make([]byte, len(r.firstIP))
				copy(targetIP, r.firstIP)
				r.appendIP(targetIP)
			}
		} else if maskSize == 112 {
			// 对于 /112 以及更大范围，我们可以在最后的16位进行迭代
			for i := uint16(0); i <= 0xFFFF; i++ {
				for j := 0; j < 2; j++ {
					r.firstIP[14+j] = byte((i >> (8*(1-j))) & 0xFF)
				}
				targetIP := make([]byte, len(r.firstIP))
				copy(targetIP, r.firstIP)
				r.appendIP(targetIP)
			}
		} else {
			// 这是原来的随机生成方法，保留作为默认处理方式
			var tempIP uint8
			for r.ipNet.Contains(r.firstIP) {
				r.firstIP[15] = randIPEndWith(255)
				r.firstIP[14] = randIPEndWith(255)

				targetIP := make([]byte, len(r.firstIP))
				copy(targetIP, r.firstIP)
				r.appendIP(targetIP)

				for i := 13; i >= 0; i-- {
					tempIP = r.firstIP[i]
					r.firstIP[i] += randIPEndWith(255)
					if r.firstIP[i] >= tempIP {
						break
					}
				}
			}
		}
	}
}


func loadIPRanges() []*net.IPAddr {
	ipRanges := newIPRanges()
	if IPText != "" {
		IPs := strings.Split(IPText, ",")
		for _, IP := range IPs {
			IP = strings.TrimSpace(IP)
			if IP == "" {
				continue
			}
			ipRanges.parseCIDR(IP)
			if isIPv4(IP) {
				ipRanges.chooseIPv4()
			} else {
				ipRanges.chooseIPv6()
			}
		}
	} else if IPFile != "" {
		file, err := os.Open(IPFile)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ipRanges.parseCIDR(line)
			if isIPv4(line) {
				ipRanges.chooseIPv4()
			} else {
				ipRanges.chooseIPv6()
			}
		}
	} else {
		cidrRanges := commonIPv4CIDRs
		if IPv6Mode {
			cidrRanges = commonIPv6CIDRs
		}
		for _, cidr := range cidrRanges {
			ipRanges.parseCIDR(cidr)
			if isIPv4(cidr) {
				ipRanges.chooseIPv4()
			} else {
				ipRanges.chooseIPv6()
			}
		}
	}
	return ipRanges.ips
}
