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
	"bufio"
	"context"
	"crypto/md5"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/goexpect"
	"github.com/google/uuid"
)

func init() {
	registerBMC(fscomBMC)
}

func fscomBMC(tags map[string]string, host string, port int, creds Credentials, exp time.Time) BMC {
	return &FSCOMBMC{
		tags:  tags,
		host:  host,
		port:  port,
		creds: creds,
		exp:   exp,
	}
}

func (b *FSCOMBMC) Type() string {
	return "FSCOM"
}

func (b *FSCOMBMC) Tags() map[string]string {
	return b.tags
}

func (b *FSCOMBMC) LEDControl() LEDControl {
	return nil
}

func (b *FSCOMBMC) PowerControl() PowerControl {
	return nil
}

func (b *FSCOMBMC) ResetControl() ResetControl {
	return nil
}

func (b *FSCOMBMC) NTPControl() NTPControl {
	return nil
}

func (b *FSCOMBMC) Credentials() (Credentials, time.Time) {
	return b.creds, b.exp
}

var (
	errRegex        = regexp.MustCompile(`^%.+$`)
	promptRegex     = regexp.MustCompile(`[0-9a-zA-Z-]+#$`)
	promptconfRegex = regexp.MustCompile(`[0-9a-zA-Z-]+\(config\)#$`)
	serialRegex     = regexp.MustCompile(`^\s+Serial Number\s+:\s+(?P<Serial>[A-Z0-9]+)$`)
	userRegex       = regexp.MustCompile(`^([a-zA-Z0-9-]+)\s+[0-9]{1,2}$`)
)

type FSCOMBMC struct {
	tags  map[string]string
	host  string
	port  int
	creds Credentials
	exp   time.Time
}

func getoutputfromcommand(e *expect.GExpect, command string, promt *regexp.Regexp, timeout time.Duration) (string, error) {
	err := e.Send(command + "\n\n")
	if err != nil {
		return "", err
	}
	res, _, err := e.Expect(promt, timeout)
	if err != nil {
		return "", fmt.Errorf("error executing command: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(res))
	for scanner.Scan() {
		line := scanner.Text()
		if errRegex.Match([]byte(line)) {
			// TODO: extract actual error
			return "", fmt.Errorf("got an error when running command")
		}
	}
	return res, nil
}

func (b *FSCOMBMC) EnsureInitialCredentials(ctx context.Context, defaultCreds []Credentials, tempPassword string) error {
	creds, err := sshFindWorkingCredentials(ctx, b.host, b.port, defaultCreds, tempPassword)
	if err != nil {
		return err
	}

	b.creds = creds
	return nil
}

func (b *FSCOMBMC) Connect(ctx context.Context) error {
	c, err := sshConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

func (b *FSCOMBMC) ReadInfo(ctx context.Context) (Info, error) {
	c, err := sshConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return Info{}, err
	}
	defer func() { must(ctx, c.Close()) }()

	timeout := 2 * time.Second
	e, _, err := expect.SpawnSSH(c, timeout, expect.Verbose(false), expect.PartialMatch(true))
	if err != nil {
		return Info{}, fmt.Errorf("can't spawn SSH client")
	}
	defer func() { must(ctx, e.Close()) }()

	_, _, err = e.Expect(promptRegex, timeout)
	if err != nil {
		return Info{}, fmt.Errorf("cannot read machine info: %w", err)
	}

	res, err := getoutputfromcommand(e, "show version", promptRegex, timeout)
	if err != nil {
		return Info{}, fmt.Errorf("cannot execute command show version: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(res))
	serial := ""
	for scanner.Scan() {
		line := scanner.Text()
		if serialRegex.Match([]byte(line)) {
			serial = serialRegex.FindStringSubmatch(line)[1]
		}
	}
	if serial == "" {
		return Info{}, fmt.Errorf("cannot determine UUID from serial")
	}

	hash := md5.Sum([]byte(serial))
	guuid, err := uuid.FromBytes(hash[:])
	if err != nil {
		return Info{}, err
	}
	ruuid := strings.ToLower(guuid.String())

	return Info{
		UUID:         ruuid,
		Type:         "Switch",
		Capabilities: []string{"credentials"},
		SerialNumber: serial,
		Manufacturer: "FSCOM",
		Power:        "On",
	}, nil
}

func (b *FSCOMBMC) CreateUser(ctx context.Context, creds Credentials, _ string) error {
	client, err := sshConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return err
	}

	timeout := 2 * time.Second
	e, _, err := expect.SpawnSSH(client, timeout, expect.Verbose(false), expect.PartialMatch(true))
	if err != nil {
		return fmt.Errorf("can't spawn SSH client")
	}
	defer func() { must(ctx, e.Close()) }()

	_, err = getoutputfromcommand(e, "configure terminal", promptconfRegex, timeout)
	if err != nil {
		return fmt.Errorf("cannot set the switch to configure mode: %w", err)
	}
	add := "username " + creds.Username + " password 0 " + creds.Password + "\n" + "username " + creds.Username + " privilege 15\n"
	_, err = getoutputfromcommand(e, add, promptconfRegex, timeout)
	if err != nil {
		return fmt.Errorf("cannot create user: %w", err)
	}

	_, err = sshConnect(ctx, b.host, b.port, creds)
	if err != nil {
		return fmt.Errorf("cannot verify credentials after creating user")
	}

	b.creds = creds
	b.exp = time.Time{}
	return nil
}

func (b *FSCOMBMC) DeleteUsers(ctx context.Context, regex *regexp.Regexp) error {
	client, err := sshConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return err
	}

	timeout := 2 * time.Second
	e, _, err := expect.SpawnSSH(client, timeout, expect.Verbose(false), expect.PartialMatch(true))
	if err != nil {
		return fmt.Errorf("can't spawn SSH client")
	}
	defer func() { must(ctx, e.Close()) }()

	res, err := getoutputfromcommand(e, "show users", promptRegex, timeout)
	if err != nil {
		return fmt.Errorf("cannot show users: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(res))
	var users []string
	for scanner.Scan() {
		line := scanner.Text()
		if userRegex.Match([]byte(line)) {
			users = append(users, userRegex.FindStringSubmatch(line)[1])
		}
	}
	if len(users) != 0 {
		// put it in configure mode
		_, err = getoutputfromcommand(e, "configure terminal\n", promptconfRegex, timeout)
		if err != nil {
			return fmt.Errorf("deleting users, cannot put switch in configure mode: %w", err)
		}
	}

	for _, user := range users {
		if user != b.creds.Username && regex.MatchString(user) {
			_, err = getoutputfromcommand(e, "no username "+user+"\n", promptconfRegex, timeout)
			if err != nil {
				return fmt.Errorf("unable to delete user %s on host %s: %w", user, b.host, err)
			}
		}
	}
	return nil
}
