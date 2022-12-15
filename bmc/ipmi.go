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
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/onmetal/oob-operator/log"
)

func init() {
	registerBMC(ipmiBMC)
}

func ipmiBMC(tags map[string]string, host string, port int, creds Credentials) BMC {
	return &IPMIBMC{
		tags:  tags,
		host:  host,
		port:  port,
		creds: creds,
	}
}

func (b *IPMIBMC) Type() string {
	return "IPMI"
}

func (b *IPMIBMC) Tags() map[string]string {
	return b.tags
}

func (b *IPMIBMC) LEDControl() LEDControl {
	return nil
}

func (b *IPMIBMC) PowerControl() PowerControl {
	return b
}

func (b *IPMIBMC) ResetControl() ResetControl {
	return b
}

func (b *IPMIBMC) NTPControl() NTPControl {
	return nil
}

func (b *IPMIBMC) Credentials() Credentials {
	return b.creds
}

type IPMIBMC struct {
	tags  map[string]string
	host  string
	port  int
	creds Credentials
}

type IPMIUser struct {
	id        string
	username  string
	enabled   bool
	available bool
}

// TODO: ipmi ciphers, should this also be tested?

func outputmap(ml string, mi *map[string]string) {
	for _, line := range strings.Split(ml, "\n") {
		colon := strings.Index(line, ":")
		if colon == -1 {
			continue
		}
		k := strings.TrimSpace(line[:colon])
		v := strings.TrimSpace(line[colon+1:])
		if k == "" {
			continue
		}
		(*mi)[k] = v
	}
}

func outputmapspace(ml string, mi *map[string]string) {
	for _, line := range strings.Split(ml, "\n") {
		line = strings.Join(strings.Fields(strings.TrimSpace(line)), " ")
		if strings.HasPrefix(line, "#") {
			continue
		}
		space := strings.Index(line, " ")
		var k, v string
		if space == -1 {
			k = line
		} else {
			k = strings.TrimSpace(line[:space])
			v = strings.TrimSpace(line[space+1:])
		}
		if k == "" {
			continue
		}
		(*mi)[k] = v
	}
}

func ipmiFindWorkingCredentials(ctx context.Context, host string, port int, defaultCreds []Credentials, tempPassword string) (Credentials, error) {
	if len(defaultCreds) == 0 {
		return Credentials{}, fmt.Errorf("no default credentials to try")
	}

	var merr error
	for _, creds := range defaultCreds {
		err := ipmiping(ctx, host, port, creds)
		if err == nil {
			return creds, nil
		}
		merr = multierror.Append(merr, err)
	}
	for _, creds := range defaultCreds {
		err := ipmiping(ctx, host, port, Credentials{creds.Username, tempPassword})
		if err == nil {
			return creds, nil
		}
		merr = multierror.Append(merr, err)
	}
	return Credentials{}, fmt.Errorf("cannot connect using any predefined credentials: %w", merr)
}

func (b *IPMIBMC) EnsureInitialCredentials(ctx context.Context, defaultCreds []Credentials, tempPassword string) error {
	creds, err := ipmiFindWorkingCredentials(ctx, b.host, b.port, defaultCreds, tempPassword)
	if err != nil {
		return err
	}

	b.creds = creds
	return nil
}

func (b *IPMIBMC) Connect(ctx context.Context) error {
	return ipmiping(ctx, b.host, b.port, b.creds)
}

func (b *IPMIBMC) ReadInfo(ctx context.Context) (Info, error) {
	log.Debug(ctx, "Reading BMC info", "host", b.host)
	info := make(map[string]string)

	out, serr, err := ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "fru", "list", "0")
	if err != nil {
		return Info{}, fmt.Errorf("cannot get fru info, stderr: %s: %w", serr, err)
	}
	outputmap(out, &info)

	out, serr, err = ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "mc", "guid")
	if err != nil {
		return Info{}, fmt.Errorf("cannot get mc info, stderr: %s: %w", serr, err)
	}
	outputmap(out, &info)

	out, serr, err = ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmi-chassis", "--get-chassis-status")
	if err != nil {
		return Info{}, fmt.Errorf("cannot get chassis status, stderr: %s: %w", serr, err)
	}
	outputmap(out, &info)

	uuid, ok := info["System GUID"]
	if !ok {
		return Info{}, fmt.Errorf("cannot determine uuid for machine")
	}
	uuid = strings.ToLower(uuid)
	powerstate, ok := info["System Power"]
	if !ok {
		return Info{}, fmt.Errorf("cannot determine the power state for machine")
	}
	serial, ok := info["Product Serial"]
	sku, ok := info["Product SKU"]
	manufacturer, ok := info["Manufacturer"]
	//TODO: currently we can't handle this correctly as we can't read the state on most hardware
	//led, ok := info["Chassis Identify State"]
	led := "Unknown"

	//TODO: properly detect if sol is supported
	return Info{
		UUID:         uuid,
		Capabilities: []string{"credentials", "power", "led", "console"},
		SerialNumber: serial,
		SKU:          sku,
		Manufacturer: manufacturer,
		LocatorLED:   led,
		Power:        cases.Title(language.English).String(powerstate),
		Console:      "ipmi",
	}, nil
}

func ipmiGenerateCommand(ctx context.Context, host string, port int, creds Credentials, cmd ...string) ([]string, error) {
	if port == 0 {
		port = 623
	}

	var command []string
	actualCmd := cmd[0]
	params := cmd[1:]
	log.Debug(ctx, "Executing IPMI command", "host", host, "command", actualCmd)
	if actualCmd == "ipmitool" {
		command = append(command, "/usr/bin/ipmitool", "-I", "lanplus", "-H", host, "-U", creds.Username, "-P", creds.Password, "-p", strconv.Itoa(port))
		command = append(command, params...)
	} else if actualCmd == "ipmi-chassis" || actualCmd == "ipmi-config" {
		// TODO: check how to provide custom port
		command = append(command, "/usr/sbin/"+actualCmd, "-D", "LAN_2_0", "-h", host, "-u", creds.Username, "-p", creds.Password)
		command = append(command, params...)
	} else {
		return command, fmt.Errorf("ipmi command not supported at the moment")
	}

	return command, nil
}

func ipmiExecuteCommand(ctx context.Context, host string, port int, creds Credentials, cmd ...string) (string, string, error) {
	command, err := ipmiGenerateCommand(ctx, host, port, creds, cmd...)
	if err != nil {
		return "", "", err
	}
	actualCmd := command[0]
	params := command[1:]
	actualCmd, err = exec.LookPath(actualCmd)
	if err != nil {
		return "", "", fmt.Errorf("%s not found in the PATH: %w", actualCmd, err)
	}
	c := exec.Command(actualCmd, params...)

	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr

	// TODO: add timeout
	err = c.Run()
	if err != nil {
		return "", "", fmt.Errorf("cannot excute command: %s, got: %w", cmd[0], err)
	}

	return string(stdout.Bytes()), string(stderr.Bytes()), nil
}

func ipmiping(ctx context.Context, host string, port int, creds Credentials) error {
	// TODO: figure out a better way to test credentials
	_, _, err := ipmiExecuteCommand(ctx, host, port, creds, "ipmitool", "lan", "print", "1")
	if err != nil {
		return fmt.Errorf("cannot use credentials for ipmi: %w", err)
	}
	return nil
}

func ipmigetusers(ctx context.Context, host string, port int, creds Credentials) ([]IPMIUser, error) {
	users := make([]IPMIUser, 0)
	// TODO: determine amount of max slots before iterating
	for i := 2; i <= 12; i++ {
		info := make(map[string]string)
		user := IPMIUser{}
		id := strconv.Itoa(i)
		out, _, err := ipmiExecuteCommand(ctx, host, port, creds, "ipmi-config", "--category=core", "--checkout", "-S", "User"+id)
		if err != nil {
			return nil, fmt.Errorf("cannot get IPMI users: %w", err)
		}
		outputmapspace(out, &info)
		username, ok := info["Username"]
		if !ok {
			// TODO: maybe better to error out
			continue
		} else {
			user.username = username
		}
		enabled, ok := info["Enable_User"]
		if !ok {
			return []IPMIUser{}, fmt.Errorf("cannot populate fields for user")
		}
		switch enabled {
		case "Yes":
			user.enabled = true
		case "No":
			user.enabled = false
		default:
			return []IPMIUser{}, fmt.Errorf("cannot populate fields for user / invalid Enable_User")
		}
		user.id = id
		users = append(users, user)
	}
	return users, nil
}

func ipmiGetFreeSlot(ctx context.Context, host string, port int, creds Credentials) (string, error) {
	users, err := ipmigetusers(ctx, host, port, creds)
	if err != nil {
		return "", fmt.Errorf("cannot determine an empty slot: %w", err)
	}
	for _, user := range users {
		if user.username == "" || !user.enabled {
			return user.id, nil
		}
	}
	return "", fmt.Errorf("no empty slot available")

}
func (b *IPMIBMC) CreateUser(ctx context.Context, creds Credentials, _ string) (time.Time, error) {
	log.Debug(ctx, "Creating user", "host", b.host, "user", creds.Username)
	slot, err := ipmiGetFreeSlot(ctx, b.host, b.port, b.creds)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot create a new user: %w", err)
	}
	_, stderr, err := ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "user", "set", "name", slot, creds.Username)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot rename user: %s, %w", stderr, err)
	}
	_, stderr, err = ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "user", "set", "password", slot, creds.Password)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot set user password: %s, %w", stderr, err)
	}
	_, stderr, err = ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "channel", "setaccess", "1", slot, "link=on", "callin=on", "privilege=4")
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot set user privileges: %s, %w", stderr, err)
	}
	_, stderr, err = ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "user", "enable", slot)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot enable user: %s, %w", stderr, err)
	}

	b.creds = creds

	t := time.Now()
	return t.AddDate(0, 0, 30), nil
}

func (b *IPMIBMC) DeleteUsers(ctx context.Context, regex *regexp.Regexp) error {
	users, err := ipmigetusers(ctx, b.host, b.port, b.creds)
	if err != nil {
		return fmt.Errorf("cannot delete users, %w", err)
	}

	for _, user := range users {
		if user.username != b.creds.Username && regex.MatchString(user.username) {
			log.Debug(ctx, "Deleting user", "user", user.username)
			_, _, err := ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "user", "disable", user.id)
			if err != nil {
				return fmt.Errorf("unable to disable user %s on host %s: %w", user.username, b.host, err)
			}
			_, _, err = ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "user", "set", "name", user.id, "")
			if err != nil {
				return fmt.Errorf("unable to reset the name of the user %s on host %s: %w", user.username, b.host, err)
			}
		}
	}
	return nil
}

func (b *IPMIBMC) PowerOn(ctx context.Context) error {
	log.Debug(ctx, "Powering on the machine")
	_, _, err := ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "chassis", "power", "on")
	if err != nil {
		return fmt.Errorf("unable to power on the server %s: %w", b.host, err)
	}

	return nil
}

func (b *IPMIBMC) Reset(ctx context.Context, immediate bool) error {
	//TODO: figure out a way of doing a graceful restart via IPMI
	if !immediate {
		return fmt.Errorf("unable to reset the server gracefully")
	}

	_, _, err := ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "chassis", "power", "reset")
	if err != nil {
		return fmt.Errorf("unable to reset the server %s: %w", b.host, err)
	}
	return nil
}

func (b *IPMIBMC) PowerOff(ctx context.Context, immediate bool) error {
	log.Debug(ctx, "Powering off the machine")
	how := ""
	if immediate {
		how = "off"
	} else {
		how = "soft"
	}
	_, _, err := ipmiExecuteCommand(ctx, b.host, b.port, b.creds, "ipmitool", "chassis", "power", how)
	if err != nil {
		return fmt.Errorf("unable to power off the system: %w", err)
	}

	return nil
}
