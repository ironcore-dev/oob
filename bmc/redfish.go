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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/stmcginnis/gofish"
	"github.com/stmcginnis/gofish/common"
	"github.com/stmcginnis/gofish/redfish"

	"github.com/onmetal/oob-operator/log"
)

func init() {
	registerBMC(redfishBMC)
}

func redfishBMC(tags map[string]string, host string, port int, creds Credentials, exp time.Time) BMC {
	return &RedfishBMC{
		tags:  tags,
		host:  host,
		port:  port,
		creds: creds,
		exp:   exp,
	}
}

type RedfishBMC struct {
	tags  map[string]string
	host  string
	port  int
	creds Credentials
	exp   time.Time
}

func (b *RedfishBMC) Type() string {
	return "Redfish"
}

func (b *RedfishBMC) Tags() map[string]string {
	return b.tags
}

func (b *RedfishBMC) LEDControl() LEDControl {
	return b
}

func (b *RedfishBMC) PowerControl() PowerControl {
	return b
}

func (b *RedfishBMC) ResetControl() ResetControl {
	return b
}

func (b *RedfishBMC) NTPControl() NTPControl {
	return b
}

func (b *RedfishBMC) Credentials() (Credentials, time.Time) {
	return b.creds, b.exp
}

var (
	userIdRegex = regexp.MustCompile(`/redfish/v1/AccountService/Accounts/([0-9]{1,2})`)
)

type redfishUser struct {
	UserName string `json:"UserName"`
	RoleID   string `json:"RoleId"`
	Password string `json:"Password"`
	Enabled  bool   `json:"Enabled"`
}

func redfishConnect(ctx context.Context, host string, port int, creds Credentials) (*gofish.APIClient, error) {
	log.Debug(ctx, "Connecting", "host", host, "user", creds.Username)

	if port == 0 {
		port = 443
	}

	config := gofish.ClientConfig{
		Endpoint: fmt.Sprintf("https://%s:%d", host, port),
		Username: creds.Username,
		Password: creds.Password,
		Insecure: true,
	}
	c, err := gofish.Connect(config)
	if err != nil {
		return nil, fmt.Errorf("cannot connect: %w", err)
	}
	return c, nil
}

func redfishGetUserIdFromError(rerr *common.Error) string {
	for _, info := range rerr.ExtendedInfos {
		for _, arg := range info.MessageArgs {
			match := userIdRegex.FindStringSubmatch(arg)
			if match != nil {
				return match[1]
			}
		}
	}
	return ""
}

func redfishFindWorkingCredentials(ctx context.Context, host string, port int, defaultCreds []Credentials, tempPassword string) (Credentials, string, error) {
	if len(defaultCreds) == 0 {
		return Credentials{}, "", fmt.Errorf("no default credentials to try")
	}

	var merr error
	var rerr *common.Error
	for _, creds := range defaultCreds {
		c, err := redfishConnect(ctx, host, port, creds)
		if err == nil {
			// TODO: optimize this
			// try now to get service accounts
			_, err := c.Service.AccountService()
			if err == nil {
				c.Logout()
				return creds, "", nil
			} else if errors.As(err, &rerr) && rerr.HTTPReturnedStatusCode == 403 {
				return creds, redfishGetUserIdFromError(rerr), nil
			}
		} else if errors.As(err, &rerr) && rerr.HTTPReturnedStatusCode == 403 {
			return creds, redfishGetUserIdFromError(rerr), nil
		}
		merr = multierror.Append(merr, err)
	}
	for _, creds := range defaultCreds {
		c, err := redfishConnect(ctx, host, port, Credentials{creds.Username, tempPassword})
		if err == nil {
			c.Logout()
			return creds, "", nil
		} else if errors.As(err, &rerr) && rerr.HTTPReturnedStatusCode == 403 {
			return creds, redfishGetUserIdFromError(rerr), nil
		}
		merr = multierror.Append(merr, err)
	}
	return Credentials{}, "", fmt.Errorf("cannot connect using any predefined credentials: %w", merr)
}

func redfishChangePasswordRaw(ctx context.Context, host string, port int, id, user, oldPassword, newPassword string) error {
	if port == 0 {
		port = 443
	}
	endpoint := fmt.Sprintf("https://%s:%d/redfish/v1/AccountService/Accounts/%s", host, port, id)
	log.Debug(ctx, "Changing password", "endpoint", endpoint)

	body, err := json.Marshal(map[string]interface{}{"Password": newPassword})
	if err != nil {
		return fmt.Errorf("cannot encode JSON: %w", err)
	}

	req, err := http.NewRequest("PATCH", endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("cannot create PATCH request: %w", err)
	}
	req.SetBasicAuth(user, oldPassword)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "gofish/1.0")

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot perform PATCH request: %w", err)
	}
	defer func() { must(ctx, response.Body.Close()) }()
	if response.StatusCode != 200 {
		return fmt.Errorf("received HTTP status %d: %s", response.StatusCode, response.Status)
	}

	return nil
}

func (b *RedfishBMC) EnsureInitialCredentials(ctx context.Context, defaultCreds []Credentials, tempPassword string) error {
	creds, pwChangeID, err := redfishFindWorkingCredentials(ctx, b.host, b.port, defaultCreds, tempPassword)
	if err != nil {
		return fmt.Errorf("cannot obtain initial credentials: %w", err)
	}

	if pwChangeID != "" {
		log.Debug(ctx, "Initial password change required", "user", creds.Username)
		err := redfishChangePasswordRaw(ctx, b.host, b.port, pwChangeID, creds.Username, creds.Password, tempPassword)
		if err != nil {
			return fmt.Errorf("cannot change password for user %s: %w", creds.Username, err)
		}

		creds.Password = tempPassword
	}

	b.creds = creds
	return nil
}

func (b *RedfishBMC) Connect(ctx context.Context) error {
	c, err := redfishConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return err
	}
	c.Logout()
	return nil
}

func redfishGetAccounts(c *gofish.APIClient) ([]*redfish.ManagerAccount, error) {
	svc, err := c.Service.AccountService()
	if err != nil {
		return nil, fmt.Errorf("cannot get account service: %w", err)
	}

	accounts, err := svc.Accounts()
	if err != nil {
		return nil, fmt.Errorf("cannot get accounts: %w", err)
	}

	return accounts, nil
}

func redfishGetUserID(accounts []*redfish.ManagerAccount, user string) string {
	for _, account := range accounts {
		if account.UserName == user {
			return account.ID
		}
	}
	return ""
}

func redfishWaitForUser(ctx context.Context, c *gofish.APIClient, host string, port int, creds Credentials, id string) (string, error) {
	var sCreds []Credentials
	sCreds = append(sCreds, creds)

	log.Debug(ctx, "Waiting for account to be ready", "username", creds.Username)

	TIMEOUT := 60

	// TODO: find a nicer way to wait for user to be available
	found := false

	for t := 0; t < TIMEOUT; t = t + 5 {
		accounts, err := redfishGetAccounts(c)
		if err != nil {
			return "", fmt.Errorf("waiting for user, cannot get users: %w", err)
		}
		for _, account := range accounts {
			if account.ID == id && account.UserName == creds.Username {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(5 * time.Second)
	}

	if !found {
		return "", fmt.Errorf("reached timeout and cannot find the created user: %s", creds.Username)
	}

	for t := 0; t < TIMEOUT; t = t + 5 {
		_, pwChangeID, err := redfishFindWorkingCredentials(ctx, host, port, sCreds, creds.Password)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		return pwChangeID, nil
	}
	return "", fmt.Errorf("reached timeout and user is not usable")
}

func redfishGetFreeID(accounts []*redfish.ManagerAccount) (string, error) {
	for _, account := range accounts {
		// modifying the user configuration t index 1 is not allowed on certain systems
		if account.UserName == "" && account.ID != "1" {
			return account.ID, nil
		}
	}
	return "", fmt.Errorf("no available free id")
}

func redfishCreateUserPost(ctx context.Context, c *gofish.APIClient, creds Credentials) (string, error) {
	log.Debug(ctx, "Creating user", "type", "POST", "user", creds.Username)

	u := redfishUser{UserName: creds.Username, RoleID: "Administrator", Password: creds.Password, Enabled: true}
	response, err := c.Post("/redfish/v1/AccountService/Accounts", u)
	if err != nil {
		return "", fmt.Errorf("cannot perform POST request: %w", err)
	}
	defer func() { must(ctx, response.Body.Close()) }()

	if response.StatusCode != 201 {
		return "", fmt.Errorf("received HTTP status %d: %s", response.StatusCode, response.Status)
	}

	m := make(map[string]interface{})
	err = json.NewDecoder(response.Body).Decode(&m)
	if err != nil {
		return "", fmt.Errorf("cannot decode response body: %w", err)
	}

	id, ok := m["Id"]
	if !ok {
		return "", fmt.Errorf("user has no Id attribute")
	}

	return fmt.Sprintf("%v", id), nil
}

func redfishCreateUserPatch(ctx context.Context, c *gofish.APIClient, slot string, creds Credentials) (string, error) {
	log.Debug(ctx, "Creating user", "type", "PATCH", "user", creds.Username)

	u := redfishUser{UserName: creds.Username, RoleID: "Administrator", Password: creds.Password, Enabled: true}
	response, err := c.Patch(fmt.Sprintf("/redfish/v1/AccountService/Accounts/%v", slot), u)
	if err != nil {
		return "", fmt.Errorf("cannot perform PATCH request: %w", err)
	}
	defer func() { must(ctx, response.Body.Close()) }()

	if response.StatusCode != 200 {
		return "", fmt.Errorf("received HTTP status %d: %s", response.StatusCode, response.Status)
	}

	m := make(map[string]interface{})
	err = json.NewDecoder(response.Body).Decode(&m)
	if err != nil {
		return "", fmt.Errorf("cannot decode response body: %w", err)
	}

	return fmt.Sprintf("%v", slot), nil
}

//func redfishChangePassword(ctx context.Context, c *gofish.APIClient, user, newPassword string) error {
//	svc, err := c.Service.AccountService()
//	if err != nil {
//		return fmt.Errorf("cannot get account service: %w", err)
//	}
//
//	accounts, err := svc.Accounts()
//	if err != nil {
//		return fmt.Errorf("cannot get accounts: %w", err)
//	}
//
//	for _, account := range accounts {
//		if account.UserName == user {
//			log.Debug(ctx, "Changing password", "user", user)
//			account.Password = newPassword
//			err = account.Update()
//			if err != nil {
//				return fmt.Errorf("cannot update account for user %s: %w", user, err)
//			}
//
//			return nil
//		}
//	}
//
//	return fmt.Errorf("user %s does not exist", user)
//}

func redfishGetPasswordExpirationRaw(ctx context.Context, host string, port int, creds Credentials, id string) (time.Time, error) {
	c, err := redfishConnect(ctx, host, port, creds)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot connect: %w", err)
	}
	defer c.Logout()

	endpoint := fmt.Sprintf("/redfish/v1/AccountService/Accounts/%s", id)
	log.Debug(ctx, "Getting password expiration", "endpoint", endpoint)

	t := time.Now()

	response, err := c.Get(endpoint)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot perform GET request: %w", err)
	}
	defer func() { must(ctx, response.Body.Close()) }()

	var expUser struct {
		PasswordExpiration *string
	}
	err = json.NewDecoder(response.Body).Decode(&expUser)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot decode response body: %w", err)
	}

	if expUser.PasswordExpiration != nil {
		t, err := time.Parse(time.RFC3339, *expUser.PasswordExpiration)
		if err != nil {
			return time.Time{}, fmt.Errorf("implement parsing of password expiration and remove this error: %s", *expUser.PasswordExpiration)
		}
		return t, nil
	}

	// check if there is a general expiration set that can't be read from the user itself
	endpoint = "/redfish/v1/AccountService"
	log.Debug(ctx, "Getting password expiration", "endpoint", endpoint)
	response, err = c.Get(endpoint)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot perform GET request: %w", err)
	}
	defer func() { must(ctx, response.Body.Close()) }()

	var expOem struct {
		Oem struct {
			Lenovo struct {
				PasswordExpirationPeriodDays *int
			}
		}
	}
	err = json.NewDecoder(response.Body).Decode(&expOem)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot decode response body: %w", err)
	}

	if expOem.Oem.Lenovo.PasswordExpirationPeriodDays != nil {
		if *expOem.Oem.Lenovo.PasswordExpirationPeriodDays == 0 {
			return time.Time{}, nil
		}
		return t.AddDate(0, 0, *expOem.Oem.Lenovo.PasswordExpirationPeriodDays), nil
	}

	return time.Time{}, nil
}

//func redfishGetPasswordExpiration(ctx context.Context, c *gofish.APIClient, id string) (time.Time, error) {
//	endpoint := fmt.Sprintf("/redfish/v1/AccountService/Accounts/%s", id)
//	log.Debug(ctx, "Getting password expiration", "endpoint", endpoint)
//
//	t := time.Now()
//
//	response, err := c.Get(endpoint)
//	if err != nil {
//		return time.Time{}, fmt.Errorf("cannot perform GET request: %w", err)
//	}
//	defer func() { must(ctx, response.Body.Close()) }()
//
//	var expUser struct {
//		PasswordExpiration *string
//	}
//	err = json.NewDecoder(response.Body).Decode(&expUser)
//	if err != nil {
//		return time.Time{}, fmt.Errorf("cannot decode response body: %w", err)
//	}
//
//	if expUser.PasswordExpiration != nil {
//		return time.Time{}, fmt.Errorf("implement parsing of password expiration and remove this error: %s", *expUser.PasswordExpiration)
//	}
//
//	// check if there is a general expiration set that can't be read from the user itself
//	endpoint = "/redfish/v1/AccountService"
//	log.Debug(ctx, "Getting password expiration", "endpoint", endpoint)
//	response, err = c.Get(endpoint)
//	if err != nil {
//		return time.Time{}, fmt.Errorf("cannot perform GET request: %w", err)
//	}
//	defer func() { must(ctx, response.Body.Close()) }()
//
//	var expOem struct {
//		Oem struct {
//			Lenovo struct {
//				PasswordExpirationPeriodDays *int
//			}
//		}
//	}
//	err = json.NewDecoder(response.Body).Decode(&expOem)
//	if err != nil {
//		return time.Time{}, fmt.Errorf("cannot decode response body: %w", err)
//	}
//
//	if expOem.Oem.Lenovo.PasswordExpirationPeriodDays != nil {
//		if *expOem.Oem.Lenovo.PasswordExpirationPeriodDays == 0 {
//			return time.Time{}, nil
//		}
//		return t.AddDate(0, 0, *expOem.Oem.Lenovo.PasswordExpirationPeriodDays), nil
//	}
//
//	return time.Time{}, nil
//}

func (b *RedfishBMC) CreateUser(ctx context.Context, creds Credentials, tempPassword string) error {
	c, err := redfishConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer c.Logout()

	accounts, err := redfishGetAccounts(c)
	if err != nil {
		return fmt.Errorf("cannot generate the list of accounts: %w", err)
	}

	if redfishGetUserID(accounts, creds.Username) != "" {
		return fmt.Errorf("user %s already exists", creds.Username)
	}

	id, err := redfishCreateUserPost(ctx, c, Credentials{creds.Username, creds.Password})
	if err != nil {
		var merr error
		merr = multierror.Append(merr, err)

		slot, err := redfishGetFreeID(accounts)
		if err != nil {
			merr = multierror.Append(merr, err)
			return fmt.Errorf("cannot create user with a POST request or get a free id: %w", merr)
		}

		id, err = redfishCreateUserPatch(ctx, c, slot, Credentials{creds.Username, creds.Password})
		if err != nil {
			merr = multierror.Append(merr, err)
			return fmt.Errorf("cannot create user with a POST request or with a PATCH request: %w", merr)
		}
	}

	pwChangeID, err := redfishWaitForUser(ctx, c, b.host, b.port, creds, id)
	if err != nil {
		var merr error
		merr = multierror.Append(merr, err)
		return fmt.Errorf("created user is not available: %w", merr)
	}

	if pwChangeID != "" {
		err := redfishChangePasswordRaw(ctx, b.host, b.port, pwChangeID, creds.Username, creds.Password, tempPassword)
		if err != nil {
			return fmt.Errorf("cannot change password for user %s: %w", creds.Username, err)
		}

		creds.Password = tempPassword
	}

	exp, err := redfishGetPasswordExpirationRaw(ctx, b.host, b.port, creds, id)
	if err != nil {
		return fmt.Errorf("cannot determine password expiration: %w", err)
	}

	b.creds = creds
	b.exp = exp
	return nil
}

func (b *RedfishBMC) ReadInfo(ctx context.Context) (Info, error) {
	c, err := redfishConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return Info{}, fmt.Errorf("cannot connect: %w", err)
	}
	defer c.Logout()

	log.Debug(ctx, "Reading BMC info")
	chassis, err := c.Service.Chassis()
	if err != nil {
		return Info{}, fmt.Errorf("cannot get chassis information: %w", err)
	}
	if len(chassis) == 0 {
		return Info{}, fmt.Errorf("cannot get chassis information")
	}
	systems, err := c.Service.Systems()
	if err != nil {
		return Info{}, fmt.Errorf("cannot get systems information: %w", err)
	}

	uuid := chassis[0].UUID
	if uuid == "" {
		log.Debug(ctx, "Reading UUID")
		response, err := c.Get("/redfish/v1/Systems/Self")
		if err != nil {
			return Info{}, fmt.Errorf("cannot perform GET request: %w", err)
		}
		defer func() { must(ctx, response.Body.Close()) }()

		m := make(map[string]interface{})
		err = json.NewDecoder(response.Body).Decode(&m)
		if err != nil {
			return Info{}, fmt.Errorf("cannot decode response body: %w", err)
		}

		id, ok := m["UUID"]
		if !ok {
			return Info{}, fmt.Errorf("BMC has no UUID attribute")
		}

		uuid = fmt.Sprintf("%v", id)
	}
	uuid = strings.ToLower(uuid)

	var led string
	switch led = string(chassis[0].IndicatorLED); led {
	case "Blinking":
		led = "Blinking"
	case "Lit":
		led = "On"
	case "Off":
		led = "Off"
	default:
		led = "Unknown"
	}

	var os, osReason string
	if len(systems) > 0 {
		sys := systems[0]
		sysRaw, err := c.Get(sys.ODataID)
		osStatus := struct {
			OEM struct {
				Lenovo struct {
					SystemStatus *string `json:"SystemStatus"`
				} `json:"Lenovo"`
			} `json:"OEM"`
		}{}

		decoder := json.NewDecoder(sysRaw.Body)
		err = decoder.Decode(&osStatus)
		if err != nil {
			return Info{}, fmt.Errorf("cannot decode information for OS status: %w", err)
		}

		if osStatus.OEM.Lenovo.SystemStatus != nil {
			if sys.PowerState == redfish.OffPowerState {
				osReason = "PoweredOff"
			} else if state := *osStatus.OEM.Lenovo.SystemStatus; state == "OSBooted" || state == "BootingOSOrInUndetectedOS" {
				os = "Ok"
				osReason = state
			} else {
				osReason = state
			}
		}
	}

	manufacturer := chassis[0].Manufacturer
	capabilities := []string{"credentials", "power", "led"}
	console := ""

	mgr, err := c.Service.Managers()
	if len(mgr) > 0 {
		consoleList := mgr[0].SerialConsole.ConnectTypesSupported
		if mgr[0].SerialConsole.ServiceEnabled {
			if strings.ToLower(manufacturer) == "lenovo" && isConsoleTypeSupported(consoleList, redfish.SSHSerialConnectTypesSupported) {
				capabilities = append(capabilities, "console")
				console = "ssh-lenovo"
			} else if isConsoleTypeSupported(consoleList, redfish.IPMISerialConnectTypesSupported) {
				capabilities = append(capabilities, "console")
				console = "ipmi"
			}
		}
	}

	return Info{
		UUID:         uuid,
		Capabilities: capabilities,
		SerialNumber: chassis[0].SerialNumber,
		SKU:          chassis[0].SKU,
		Manufacturer: manufacturer,
		LocatorLED:   led,
		Power:        fmt.Sprintf("%v", chassis[0].PowerState),
		OS:           os,
		OSReason:     osReason,
		Console:      console,
	}, nil
}

func isConsoleTypeSupported(consoleList []redfish.SerialConnectTypesSupported, console redfish.SerialConnectTypesSupported) bool {
	for _, sc := range consoleList {
		if sc == console {
			return true
		}
	}
	return false
}

func (b *RedfishBMC) SetLocatorLED(ctx context.Context, state string) (string, error) {
	c, err := redfishConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return "", fmt.Errorf("cannot connect: %w", err)
	}
	defer c.Logout()

	log.Debug(ctx, "Setting the LED on the machine")

	systems, err := c.Service.Systems()

	if err != nil {
		return "", fmt.Errorf("unable to get the systems: %w", err)
	}

	var ledState common.IndicatorLED
	switch state {
	case "On":
		ledState = common.LitIndicatorLED
	case "Blinking":
		ledState = common.BlinkingIndicatorLED
	case "Off":
		ledState = common.OffIndicatorLED
	default:
		return "", fmt.Errorf("unable to set LED state to unknown")
	}

	systems[0].IndicatorLED = ledState
	err = systems[0].Update()

	if err != nil {
		return "", fmt.Errorf("unable to set the LED: %w", err)
	}

	return state, nil
}

func (b *RedfishBMC) PowerOn(ctx context.Context) error {
	c, err := redfishConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer c.Logout()

	log.Debug(ctx, "Powering on the machine")

	systems, err := c.Service.Systems()

	if err != nil {
		return fmt.Errorf("unable to get the systems: %w", err)
	}

	err = systems[0].Reset(redfish.OnResetType)
	if err != nil {
		return fmt.Errorf("unable to power on the system: %w", err)
	}

	return nil
}

func (b *RedfishBMC) Reset(ctx context.Context, immediate bool) error {
	c, err := redfishConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer c.Logout()

	log.Debug(ctx, "Resetting the machine")

	systems, err := c.Service.Systems()

	if err != nil {
		return fmt.Errorf("unable to get the systems: %w", err)
	}

	if immediate {
		err = systems[0].Reset(redfish.ForceRestartResetType)
	} else {
		err = systems[0].Reset(redfish.GracefulRestartResetType)
	}
	if err != nil {
		return fmt.Errorf("unable to reset the system: %w", err)
	}

	return nil
}

func (b *RedfishBMC) PowerOff(ctx context.Context, immediate bool) error {
	c, err := redfishConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer c.Logout()

	log.Debug(ctx, "Powering off the machine")

	systems, err := c.Service.Systems()

	if err != nil {
		return fmt.Errorf("unable to get the systems: %w", err)
	}

	if immediate {
		err = systems[0].Reset(redfish.ForceOffResetType)
	} else {
		err = systems[0].Reset(redfish.GracefulShutdownResetType)
	}
	if err != nil {
		return fmt.Errorf("unable to power off the system: %w", err)
	}

	return nil
}

func (b *RedfishBMC) DeleteUsers(ctx context.Context, regex *regexp.Regexp) error {
	c, err := redfishConnect(ctx, b.host, b.port, b.creds)
	if err != nil {
		return fmt.Errorf("cannot connect: %w", err)
	}
	defer c.Logout()
	svc, err := c.Service.AccountService()
	if err != nil {
		return fmt.Errorf("cannot get account service: %w", err)
	}

	accounts, err := svc.Accounts()
	if err != nil {
		return fmt.Errorf("cannot get accounts: %w", err)
	}

	for _, account := range accounts {
		if account.UserName != b.creds.Username && regex.MatchString(account.UserName) {
			log.Debug(ctx, "Deleting user", "user", account.UserName)
			_, err := c.Delete(account.ODataID)
			if err != nil {
				account.Enabled = false
				account.UserName = ""
				err = account.Update()
				if err != nil {
					return fmt.Errorf("cannot delete user %s: %w", account.UserName, err)
				}
			}
		}
	}
	return nil
}

func (b *RedfishBMC) SetNTPServers(_ context.Context, _ []string) error {
	// TODO: implement NTP
	return nil
}
