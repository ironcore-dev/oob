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
	"time"

	"github.com/onmetal/oob-operator/log"
)

type BMC interface {
	Type() string
	Tags() map[string]string
	Credentials() (Credentials, time.Time)
	EnsureInitialCredentials(ctx context.Context, defaultCreds []Credentials, tempPassword string) error
	Connect(ctx context.Context) error
	CreateUser(ctx context.Context, creds Credentials, tempPassword string) error
	DeleteUsers(ctx context.Context, regex *regexp.Regexp) error
	ReadInfo(ctx context.Context) (Info, error)
}

type LEDControl interface {
	SetLocatorLED(ctx context.Context, state string) (string, error)
}

type PowerControl interface {
	PowerOn(ctx context.Context) error
	PowerOff(ctx context.Context, immediate bool) error
}

type ResetControl interface {
	Reset(ctx context.Context, immediate bool) error
}

type NTPControl interface {
	SetNTPServers(ctx context.Context, ntpServers []string) error
}

type newBMCFunc func(tags map[string]string, host string, port int, creds Credentials, exp time.Time) BMC

var (
	bmcs = make(map[string]newBMCFunc)
)

func registerBMC(newFunc newBMCFunc) {
	bmcs[newFunc(nil, "", 0, Credentials{}, time.Time{}).Type()] = newFunc
}

func NewBMC(typ string, tags map[string]string, host string, port int, creds Credentials, exp time.Time) (BMC, error) {
	newFunc, ok := bmcs[typ]
	if !ok {
		return nil, fmt.Errorf("BMC of type %s is not supported", typ)
	}

	return newFunc(tags, host, port, creds, exp), nil
}

type Credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Info struct {
	UUID         string
	Type         string
	Capabilities []string
	SerialNumber string
	SKU          string
	Manufacturer string
	LocatorLED   string
	Power        string
	OS           string
	OSReason     string
	Console      string
}

func must(ctx context.Context, err error) {
	if err != nil {
		log.Error(ctx, fmt.Errorf("impossible error (this should never happen lol): %w", err))
	}
}
