package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"openpak/np-common/coreclient"
	"openpak/np-common/nphttp"
	"openpak/np-common/ticket"
	"openpak/np-matching2/client"
	"openpak/np-matching2/front"
	"openpak/np-matching2/wire"
	"os"
	"time"
)

// testclient is a headless second player run inside the container: `np-matching2 testclient <online id> [leave]`. It logs in as another
// test account (a ticket issued with the agent's own key; the account must exist in the core), searches the rooms of the group and joins
// the newest one, printing what the firmware would receive. Test accounts (@openpak.org) only.
func testclient(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: testclient <online id>")
	}
	ctx := context.Background()
	core, err := coreclient.Dial(nphttp.Env("NP_CORE_ADDR", "localhost:7000"), os.Getenv("NP_CORE_KEY"))
	if err != nil {
		return err
	}
	defer core.Close()
	link, err := core.GetLinkByOnlineID(ctx, args[0])
	if err != nil {
		return fmt.Errorf("account %s: %w", args[0], err)
	}
	signer, err := ticket.Load(os.Getenv("NP_TICKET_KEY"))
	if err != nil {
		return err
	}
	tk, err := signer.Issue(ticket.Identity{AccountID: link.AccountID, LinkID: link.LinkID, OnlineID: link.OnlineID, Country: "pt", Service: "IV0001-NPXS01001_00"}, time.Hour)
	if err != nil {
		return err
	}
	const comm = "NPWR04270_00"
	titles, err := loadTitles()
	if err != nil {
		return err
	}
	c := &client.Client{Comm: comm, Pass: titles[comm].Pass}
	if c.Plain, err = net.Dial("tcp", "127.0.0.1:3480"); err != nil {
		return err
	}
	tc, err := net.Dial("tcp", "127.0.0.1:8443")
	if err != nil {
		return err
	}
	c.TLS = tls.Client(tc, &tls.Config{ServerName: front.AgentName, InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA}})
	if _, err := c.Ping(); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	if _, err := c.Login(tk, link.OnlineID, link.OnlineID); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	fmt.Println("logged in as", link.OnlineID)
	if _, err := c.Call(wire.CmdWorldList); err != nil {
		return fmt.Errorf("world list: %w", err)
	}
	sf, err := c.Call(0x1200)
	if err != nil {
		return fmt.Errorf("search: %w", err)
	}
	s := sf.Elements()[0x03]
	if len(s) < 8 {
		return fmt.Errorf("search reply too short")
	}
	n := int(binary.BigEndian.Uint16(s[2:]))
	fmt.Println("search: rooms =", n)
	if n == 0 {
		return fmt.Errorf("no room to join")
	}
	// first item: 0x45 TLV starts at s[8]; its value starts at s[12]: three u16 = low 48 bits of the room id
	a, b, cc := binary.BigEndian.Uint16(s[12:]), binary.BigEndian.Uint16(s[14:]), binary.BigEndian.Uint16(s[16:])
	fmt.Printf("room id parts: %04x %04x %04x\n", a, b, cc)
	jf, err := c.Call(0x3201, wire.TLV(0x3e, 4, binary.BigEndian.AppendUint16(nil, cc)))
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	for _, id := range []uint16{0x16, 0x24, 0x3a, 0x21, 0x71, 0x02} {
		fmt.Printf("0x3201 reply element 0x%02x: %d bytes\n", id, len(jf.Elements()[id]))
	}
	fmt.Println("member id:", hex.EncodeToString(jf.Elements()[0x16]))
	if len(args) > 1 && args[1] == "leave" {
		if _, err := c.Call(0x3202); err != nil {
			return err
		}
		fmt.Println("left")
	}
	return nil
}
