//go:build linux
// +build linux

// Package netdev provides a syscall-based network device implementation for Linux.
// This enables TinyGo's net package to use native Linux sockets.
package netdev

import (
	"errors"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

// Socket constants
const (
	AF_INET     = 2
	SOCK_STREAM = 1
	SOCK_DGRAM  = 2
	IPPROTO_TCP = 6
	IPPROTO_UDP = 17
	SOL_SOCKET  = 1
	SO_REUSEADDR = 2
)

// LinuxNetdev implements the netdever interface using Linux syscalls
type LinuxNetdev struct{}

// NewLinuxNetdev creates a new Linux network device
func NewLinuxNetdev() *LinuxNetdev {
	return &LinuxNetdev{}
}

// GetHostByName resolves a hostname to an IP address
func (n *LinuxNetdev) GetHostByName(name string) (netip.Addr, error) {
	// For now, only support numeric IP addresses
	addr, err := netip.ParseAddr(name)
	if err != nil {
		return netip.Addr{}, errors.New("DNS lookup not implemented, use IP address")
	}
	return addr, nil
}

// Addr returns the local IP address
func (n *LinuxNetdev) Addr() (netip.Addr, error) {
	// Return a default address - in a real implementation this would
	// query the network interfaces
	return netip.MustParseAddr("0.0.0.0"), nil
}

// Socket creates a new socket
func (n *LinuxNetdev) Socket(domain int, stype int, protocol int) (int, error) {
	fd, _, errno := syscall.Syscall(syscall.SYS_SOCKET, uintptr(domain), uintptr(stype), uintptr(protocol))
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// sockaddrInet4 is the raw sockaddr_in structure
type sockaddrInet4 struct {
	Family uint16
	Port   uint16
	Addr   [4]byte
	Zero   [8]byte
}

// Bind binds a socket to a local address
func (n *LinuxNetdev) Bind(sockfd int, addr netip.AddrPort) error {
	sa := sockaddrInet4{
		Family: AF_INET,
		Port:   htons(addr.Port()),
	}
	if addr.Addr().Is4() {
		a4 := addr.Addr().As4()
		copy(sa.Addr[:], a4[:])
	}

	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(sockfd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 {
		return errno
	}
	return nil
}

// Connect connects a socket to a remote address
func (n *LinuxNetdev) Connect(sockfd int, host string, addr netip.AddrPort) error {
	sa := sockaddrInet4{
		Family: AF_INET,
		Port:   htons(addr.Port()),
	}
	if addr.Addr().Is4() {
		a4 := addr.Addr().As4()
		copy(sa.Addr[:], a4[:])
	}

	_, _, errno := syscall.Syscall(syscall.SYS_CONNECT, uintptr(sockfd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 {
		return errno
	}
	return nil
}

// Listen marks a socket as listening
func (n *LinuxNetdev) Listen(sockfd int, backlog int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_LISTEN, uintptr(sockfd), uintptr(backlog), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// Accept accepts a connection on a listening socket
func (n *LinuxNetdev) Accept(sockfd int) (int, netip.AddrPort, error) {
	var sa sockaddrInet4
	addrlen := unsafe.Sizeof(sa)

	fd, _, errno := syscall.Syscall(syscall.SYS_ACCEPT, uintptr(sockfd), uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&addrlen)))
	if errno != 0 {
		return -1, netip.AddrPort{}, errno
	}

	addr := netip.AddrFrom4(sa.Addr)
	port := ntohs(sa.Port)

	return int(fd), netip.AddrPortFrom(addr, port), nil
}

// Send sends data on a connected socket
func (n *LinuxNetdev) Send(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	// TODO: implement deadline handling with poll/select
	sent, _, errno := syscall.Syscall6(syscall.SYS_SENDTO, uintptr(sockfd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(flags), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(sent), nil
}

// Recv receives data from a connected socket
func (n *LinuxNetdev) Recv(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	// TODO: implement deadline handling with poll/select
	received, _, errno := syscall.Syscall6(syscall.SYS_RECVFROM, uintptr(sockfd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(flags), 0, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(received), nil
}

// SendTo sends data to a specific address (for UDP)
func (n *LinuxNetdev) SendTo(sockfd int, buf []byte, flags int, addr netip.AddrPort, deadline time.Time) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	sa := sockaddrInet4{
		Family: AF_INET,
		Port:   htons(addr.Port()),
	}
	if addr.Addr().Is4() {
		a4 := addr.Addr().As4()
		copy(sa.Addr[:], a4[:])
	}

	sent, _, errno := syscall.Syscall6(syscall.SYS_SENDTO, uintptr(sockfd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(flags), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 {
		return -1, errno
	}
	return int(sent), nil
}

// RecvFrom receives data and returns the sender's address (for UDP)
func (n *LinuxNetdev) RecvFrom(sockfd int, buf []byte, flags int, deadline time.Time) (int, netip.AddrPort, error) {
	if len(buf) == 0 {
		return 0, netip.AddrPort{}, nil
	}

	var sa sockaddrInet4
	addrlen := unsafe.Sizeof(sa)

	// TODO: implement deadline handling with poll/select
	received, _, errno := syscall.Syscall6(syscall.SYS_RECVFROM, uintptr(sockfd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(flags), uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&addrlen)))
	if errno != 0 {
		return -1, netip.AddrPort{}, errno
	}

	addr := netip.AddrFrom4(sa.Addr)
	port := ntohs(sa.Port)

	return int(received), netip.AddrPortFrom(addr, port), nil
}

// Close closes a socket
func (n *LinuxNetdev) Close(sockfd int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_CLOSE, uintptr(sockfd), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// SetSockOpt sets a socket option
func (n *LinuxNetdev) SetSockOpt(sockfd int, level int, opt int, value interface{}) error {
	// Basic implementation - expand as needed
	switch v := value.(type) {
	case int:
		val := int32(v)
		_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(sockfd), uintptr(level), uintptr(opt), uintptr(unsafe.Pointer(&val)), 4, 0)
		if errno != 0 {
			return errno
		}
	default:
		return errors.New("unsupported socket option type")
	}
	return nil
}

// htons converts host byte order to network byte order (16-bit)
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// ntohs converts network byte order to host byte order (16-bit)
func ntohs(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
