package wiredialer

import (
	"context"
	"io"
	"net"
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/beppler/sproxy/internal/wiredialer/config"
)

type WireDialer struct {
	tun    tun.Device
	tnet   *netstack.Net
	device *device.Device
}

func (d *WireDialer) Dial(network, address string) (net.Conn, error) {
	return d.tnet.Dial(network, address)
}

func (d *WireDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.tnet.DialContext(ctx, network, address)
}

func NewDialerFromFile(path string) (*WireDialer, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return NewDialerFromConfiguration(file)
}

func NewDialerFromConfiguration(reader io.Reader) (*WireDialer, error) {
	iface_addresses, dns_addresses, mtu, ipcConfig, err := config.ParseConfig(reader)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(
		iface_addresses,
		dns_addresses,
		mtu)
	if err != nil {
		return nil, err
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))

	err = dev.IpcSet(ipcConfig)
	if err != nil {
		tun.Close()
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		dev.Close()
		tun.Close()
		return nil, err
	}

	return &WireDialer{
		tun:    tun,
		tnet:   tnet,
		device: dev,
	}, nil
}
