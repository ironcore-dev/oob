/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bmc

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	expect "github.com/google/goexpect"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/crypto/ssh"

	"github.com/onmetal/oob-operator/log"
)

func init() {
	registerBMC(sshBMC)
}

func sshBMC(tags map[string]string, host string, port int, creds Credentials) BMC {
	return &SSHBMC{
		tags:  tags,
		host:  host,
		port:  port,
		creds: creds,
	}
}

func (b *SSHBMC) Type() string {
	return "SSH"
}

func (b *SSHBMC) Tags() map[string]string {
	return b.tags
}

func (b *SSHBMC) LEDControl() LEDControl {
	return nil
}

func (b *SSHBMC) PowerControl() PowerControl {
	return nil
}

func (b *SSHBMC) ResetControl() ResetControl {
	return nil
}

func (b *SSHBMC) NTPControl() NTPControl {
	return nil
}

func (b *SSHBMC) Credentials() Credentials {
	return b.creds
}

func (b *SSHBMC) Capabilities() Capabilities {
	return b
}

type SSHBMC struct {
	tags  map[string]string
	host  string
	port  int
	creds Credentials
}

var sshscript = `for i in $(find /sys/class/dmi/id/ -type f); do 
echo "$(basename $i):$(sudo cat $i 2> /dev/null)"
done`

var fields = map[string]string{
	"UUID":          "product_uuid",
	"ChassisSerial": "chassis_serial",
	"ProductSerial": "product_serial",
	"Manufacturer":  "chassis_vendor",
	"SKU":           "product_sku",
}

var namespaceForUUID = "onmetal.de"
var sshCapabilities = []string{"credentials"}

func sshConnect(ctx context.Context, host string, port int, creds Credentials) (*ssh.Client, error) {
	log.Debug(ctx, "Connecting via SSH", "host", host, "user", creds.Username)
	sshConfig := &ssh.ClientConfig{
		User: creds.Username,
		Auth: []ssh.AuthMethod{ssh.Password(creds.Password)},
	}
	sshConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()

	if port == 0 {
		port = 22
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), sshConfig)
	if err != nil {
		return nil, fmt.Errorf("cannot connect: %w", err)
	}

	return client, nil
}

func sshRunCommand(_ context.Context, c *ssh.Client, command string) (string, error) {
	session, err := c.NewSession()
	if err != nil {
		return "", fmt.Errorf("cannot create a SSH session: %w", err)
	}
	defer func() { _ = session.Close() }()

	out, err := session.Output(command)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(out), "\n"), err
}

func verifyLinux(ctx context.Context, c *ssh.Client) (bool, error) {
	out, err := sshRunCommand(ctx, c, "uname")
	if err != nil {
		return false, fmt.Errorf("cannot verify that host is a Linux machine: %w", err)
	}

	if out == "Linux" {
		return true, nil
	}
	return false, nil
}

func sshFindWorkingCredentials(ctx context.Context, host string, port int, defaultCreds []Credentials, tempPassword string) (Credentials, error) {
	if len(defaultCreds) == 0 {
		return Credentials{}, fmt.Errorf("no default credentials to try")
	}

	var merr error
	for _, creds := range defaultCreds {
		c, err := sshConnect(ctx, host, port, creds)
		if err == nil {
			err = c.Close()
			if err == nil {
				return creds, nil
			}
		}
		merr = multierror.Append(merr, err)
	}
	for _, creds := range defaultCreds {
		c, err := sshConnect(ctx, host, port, Credentials{creds.Username, tempPassword})
		if err == nil {
			err = c.Close()
			if err == nil {
				return creds, nil
			}
		}
		merr = multierror.Append(merr, err)
	}
	return Credentials{}, fmt.Errorf("cannot connect using any predefined credentials: %w", merr)
}

func (b *SSHBMC) EnsureInitialCredentials(ctx context.Context, defaultCreds []Credentials, tempPassword string) error {
	// No special stuff needed here, no initial password change and so on
	creds, err := sshFindWorkingCredentials(ctx, b.host, b.port, defaultCreds, tempPassword)
	if err != nil {
		return err
	}

	b.creds = creds
	return nil
}

func (b *SSHBMC) Connect(ctx context.Context) error {
	c, err := sshConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

func (b *SSHBMC) ReadInfo(ctx context.Context) (Info, error) {
	info := make(map[string]string)

	c, err := sshConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return Info{}, err
	}
	defer func() { must(ctx, c.Close()) }()

	vl, err := verifyLinux(ctx, c)
	if err != nil {
		return Info{}, fmt.Errorf("cannot read machine info: %w", err)
	}
	if !vl {
		return Info{}, fmt.Errorf("cannot read machine info from non Linux system")
	}

	out, err := sshRunCommand(ctx, c, sshscript)
	if err != nil {
		return Info{}, err
	}

	outputmap(out, &info)

	ruuid := info[fields["UUID"]]

	serial := info[fields["ProductSerial"]]
	if serial == "" || serial == "None" {
		serial = info[fields["ChassisSerial"]]
	}

	uuidSource := b.tags["uuidSrc"]
	if uuidSource != "" {
		s, ok := fields[uuidSource]
		if !ok {
			return Info{}, fmt.Errorf("no such field exists: %s", uuidSource)
		}
		namespaceUUID := uuid.NewMD5(uuid.UUID{}, []byte(namespaceForUUID))
		guuid := uuid.NewMD5(namespaceUUID, []byte(info[s]))
		ruuid = guuid.String()
	}
	ruuid = strings.ToLower(ruuid)

	return Info{
		UUID:         ruuid,
		SerialNumber: serial,
		SKU:          info[fields["SKU"]],
		Manufacturer: info[fields["Manufacturer"]],
		Power:        "On",
	}, nil
}

func sshUserAddCommand(user string) string {
	useradd := fmt.Sprintf(`(sudo adduser %s --gecos "GOM" --disabled-password || sudo useradd -b /home/%s -s /bin/sh -m %s)`, user, user, user)
	usermod := fmt.Sprintf(`sudo usermod -aG $(awk -F: '$1 ~ /sudo|wheel/{printf "%%s%%s", s, $1; s=","}' /etc/group) %s`, user)
	chage := fmt.Sprintf(`sudo chage -E -1 -M -1 %s`, user)
	return fmt.Sprintf(`%s && %s && %s`, useradd, usermod, chage)
}

func (b *SSHBMC) CreateUser(ctx context.Context, creds Credentials, _ string) (time.Time, error) {
	client, err := sshConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return time.Time{}, err
	}

	_, err = sshRunCommand(ctx, client, sshUserAddCommand(creds.Username))
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot add username %s on host %s: %w", creds.Username, b.host, err)
	}

	err = sshChangePassword(ctx, b.host, b.port, b.creds, creds)
	if err != nil {
		return time.Time{}, err
	}

	b.creds = creds

	t := time.Now()
	return t.AddDate(0, 0, 30), nil
}

func sshChangePassword(ctx context.Context, host string, port int, creds, newCreds Credentials) error {
	client, err := sshConnect(ctx, host, port, creds)
	if err != nil {
		return err
	}
	defer func() { must(ctx, client.Close()) }()

	timeout := 5 * time.Second
	e, _, err := expect.SpawnSSH(client, timeout, expect.Verbose(false), expect.PartialMatch(true))
	if err != nil {
		return fmt.Errorf("cannot spawn SSH client: %w", err)
	}
	defer func() { must(ctx, e.Close()) }()

	_, err = e.ExpectBatch([]expect.Batcher{
		&expect.BSnd{S: "sudo passwd " + newCreds.Username + "\n"},
		&expect.BExp{R: "New password:"},
		&expect.BSnd{S: newCreds.Password + "\n"},
		&expect.BExp{R: "Retype new password:"},
		&expect.BSnd{S: newCreds.Password + "\n"},
		&expect.BExp{R: "passwd: password updated successfully"},
	}, timeout)

	if err != nil {
		return fmt.Errorf("cannot change the password for user %s on host %s: %w", newCreds.Username, host, err)
	}

	return nil
}

func (b *SSHBMC) DeleteUsers(ctx context.Context, regex *regexp.Regexp) error {
	client, err := sshConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return err
	}

	out, err := sshRunCommand(ctx, client, "getent passwd | cut -d: -f1")
	if err != nil {
		return fmt.Errorf("cannot list the users on host: %s: %w", b.host, err)
	}

	users := strings.Split(out, "\n")
	for _, user := range users {
		if user != b.creds.Username && regex.MatchString(user) {
			// TODO: enable actual deletion
			//_, err = sshRunCommand(ctx, client, fmt.Sprintf("sudo userdel -fr %s", user))
			_, err = sshRunCommand(ctx, client, fmt.Sprintf("echo %s", user))
			if err != nil {
				return fmt.Errorf("unable to delete user %s on host %s: %w", user, b.host, err)
			}
		}
	}

	return nil
}

func (b *SSHBMC) GetCapabilities(_ context.Context) ([]string, error) {
	return sshCapabilities, nil
}
