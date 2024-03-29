// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/sethvargo/go-password/password"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	oobv1alpha1 "github.com/ironcore-dev/oob/api/v1alpha1"
	"github.com/ironcore-dev/oob/bmc"
	"github.com/ironcore-dev/oob/internal/condition"
	"github.com/ironcore-dev/oob/internal/log"
	"github.com/ironcore-dev/oob/internal/rand"
)

//+kubebuilder:rbac:groups=ironcore.dev,resources=oobs,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ironcore.dev,resources=oobs/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ironcore.dev,resources=oobs/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func NewOOBReconciler(namespace string, credentialsExpBuffer, shutdownTimeout time.Duration) (*OOBReconciler, error) {
	return &OOBReconciler{
		namespace:            namespace,
		credentialsExpBuffer: credentialsExpBuffer,
		shutdownTimeout:      shutdownTimeout,
	}, nil
}

// OOBReconciler reconciles a OOB object
type OOBReconciler struct {
	client.Client
	namespace            string
	credentialsExpBuffer time.Duration
	shutdownTimeout      time.Duration
	disabled             bool
	disabledMtx          sync.RWMutex
	macPrefixes          prefixMap
	usernamePrefix       string
	usernameRegex        *regexp.Regexp
	temporaryPassword    string
	ntpServers           []string
}

type tag struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

type accessInfo struct {
	Protocol           string            `yaml:"protocol"`
	Tags               []tag             `yaml:"tags"`
	Port               int               `yaml:"port"`
	DefaultCredentials []bmc.Credentials `yaml:"defaultCredentials"`
	UUIDSource         string            `yaml:"uuidSource"`
	Disregard          bool              `yaml:"disregard"`
}

type prefixMap map[string]accessInfo

func (m prefixMap) get(mac string) (accessInfo, bool) {
	for i := len(mac); i > 0; i-- {
		if mac[i-1] == ':' {
			continue
		}
		prefix := mac[:i]
		l, ok := m[prefix]
		if ok {
			return l, true
		}
	}
	return accessInfo{}, false
}

//func (r *OOBReconciler) enable() {
//	r.disabledMtx.Lock()
//	defer r.disabledMtx.Unlock()
//	r.disabled = false
//}

func (r *OOBReconciler) disable() {
	r.disabledMtx.Lock()
	defer r.disabledMtx.Unlock()
	r.disabled = true
}

// LoadMACPrefixes loads MAC address prefixes from a file.
func (r *OOBReconciler) LoadMACPrefixes(ctx context.Context, prefixesFile string) error {
	type macPrefixEntry struct {
		MACPrefix  string     `yaml:"macPrefix"`
		AccessInfo accessInfo `yaml:",inline"`
	}

	type macPrefixesConfig struct {
		TemporaryPassword string           `yaml:"temporaryPassword"`
		UsernamePrefix    string           `yaml:"usernamePrefix"`
		MACPrefixes       []macPrefixEntry `yaml:"macPrefixes"`
		NTPServers        []string         `yaml:"ntpServers"`
	}

	prefixesData, err := os.ReadFile(prefixesFile)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", prefixesFile, err)
	}

	var config macPrefixesConfig
	err = yaml.Unmarshal(prefixesData, &config)
	if err != nil {
		return fmt.Errorf("cannot unmarshal %s: %w", prefixesFile, err)
	}

	if config.TemporaryPassword == "" {
		return fmt.Errorf("a temporary password must be provided in the MAC prefixes configuration")
	}
	r.temporaryPassword = config.TemporaryPassword

	r.usernamePrefix = config.UsernamePrefix
	if r.usernamePrefix == "" {
		r.usernamePrefix = "metal-"
	}
	r.usernameRegex, err = regexp.Compile(r.usernamePrefix + `[a-z]{6}`)
	if err != nil {
		return fmt.Errorf("cannot compile username regex: %w", err)
	}

	if len(config.NTPServers) == 0 {
		return fmt.Errorf("a list of NTP servers must be provided")
	}
	r.ntpServers = config.NTPServers

	r.macPrefixes = make(map[string]accessInfo, len(config.MACPrefixes))
	for _, e := range config.MACPrefixes {
		r.macPrefixes[e.MACPrefix] = e.AccessInfo
	}

	log.Info(ctx, "Loaded MAC prefixes", "count", len(r.macPrefixes))
	return nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *OOBReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.disabledMtx.RLock()
	defer r.disabledMtx.RUnlock()
	if r.disabled {
		return ctrl.Result{}, nil
	}

	return r.reconcile(ctx, req)
}

func (r *OOBReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var oob oobv1alpha1.OOB
	err := r.Get(ctx, req.NamespacedName, &oob)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get OOB: %w", err))
	}

	ctx = log.WithValues(ctx, "mac", oob.Status.Mac, "ip", oob.Status.IP, "uuid", oob.Status.UUID)
	log.Debug(ctx, "Reconciling")

	// Clear None fields
	var stop bool
	stop, err = r.clearNoneFields(ctx, &oob)
	if err != nil {
		return ctrl.Result{}, err
	}
	if stop {
		log.Debug(ctx, "Reconciled successfully")
		return ctrl.Result{}, nil
	}

	// Don't do anything if there is no IP or MAC
	if oob.Status.IP == "" || oob.Status.Mac == "" {
		log.Debug(ctx, "Missing IP or MAC, ignoring OOB")
		log.Debug(ctx, "Reconciled successfully")
		return ctrl.Result{}, nil
	}

	// Ensure that the OOB has working persisted credentials
	var bmctrl bmc.BMC
	var msgErr error
	bmctrl, stop, msgErr, err = r.ensureGoodCredentials(ctx, &oob)
	if err != nil {
		return ctrl.Result{}, err
	}
	if msgErr != nil {
		return ctrl.Result{Requeue: true}, r.applyErrorCondition(ctx, &oob, msgErr)
	}
	if bmctrl != nil {
		ctx = log.WithValues(ctx, "proto", bmctrl.Type())
	}
	if stop {
		log.Debug(ctx, "Reconciled successfully")
		return ctrl.Result{}, nil
	}

	// Read OOB info
	log.Debug(ctx, "Retrieving OOB information")
	var info bmc.Info
	info, err = bmctrl.ReadInfo(ctx)
	if err != nil {
		return ctrl.Result{Requeue: true}, r.applyErrorCondition(ctx, &oob, fmt.Errorf("cannot retrieve OOB information: %w", err))
	}

	// Ensure that the OOB has the correct name and UUID
	stop, err = r.ensureCorrectUUIDandName(ctx, &oob, info.UUID)
	if err != nil {
		return ctrl.Result{}, err
	}
	ctx = log.WithValues(ctx, "uuid", oob.Status.UUID)
	if stop {
		log.Debug(ctx, "Reconciled successfully")
		return ctrl.Result{}, nil
	}

	// Set NTP servers
	err = r.setNTPServers(ctx, bmctrl)
	if err != nil {
		return ctrl.Result{Requeue: true}, r.applyErrorCondition(ctx, &oob, err)
	}

	requeueAfter := time.Hour * 24
	specChanged := false

	// Set all status fields
	statusChanged := r.setStatusFields(&oob, &info, &requeueAfter)

	// Apply any changes to the locator LED
	err = r.applyLocatorLED(ctx, &oob, bmctrl, &specChanged, &statusChanged)
	if err != nil {
		return ctrl.Result{Requeue: true}, r.applyErrorCondition(ctx, &oob, err)
	}

	// Apply anu changes to the power state
	err = r.applyPower(ctx, &oob, bmctrl, &specChanged, &statusChanged, &requeueAfter)
	if err != nil {
		return ctrl.Result{Requeue: true}, r.applyErrorCondition(ctx, &oob, err)
	}

	// Apply anu reset request
	err = r.applyReset(ctx, &oob, bmctrl, &specChanged, &statusChanged, &requeueAfter)
	if err != nil {
		return ctrl.Result{Requeue: true}, r.applyErrorCondition(ctx, &oob, err)
	}

	// Apply any changes to the OOB status
	if statusChanged {
		spec := oob.Spec
		oob = oobv1alpha1.OOB{
			TypeMeta: metav1.TypeMeta{
				APIVersion: oobv1alpha1.GroupVersion.String(),
				Kind:       "OOB",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: oob.Namespace,
				Name:      oob.Name,
			},
			Status: oobv1alpha1.OOBStatus{
				Type:             oob.Status.Type,
				Capabilities:     oob.Status.Capabilities,
				Manufacturer:     oob.Status.Manufacturer,
				SKU:              oob.Status.SKU,
				SerialNumber:     oob.Status.SerialNumber,
				LocatorLED:       oob.Status.LocatorLED,
				Power:            oob.Status.Power,
				ShutdownDeadline: oob.Status.ShutdownDeadline,
				OS:               oob.Status.OS,
				OSReason:         oob.Status.OSReason,
				OSReadDeadline:   oob.Status.OSReadDeadline,
				Console:          oob.Status.Console,
				FWVersion:        oob.Status.FWVersion,
			},
		}

		// Apply the OOB
		log.Info(ctx, "Applying OOB status")
		err = r.Status().Patch(ctx, &oob, client.Apply, client.FieldOwner("oob.ironcore.dev/oob/machine"), client.ForceOwnership)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot apply OOB status: %w", err)
		}
		oob.Spec = spec
	}

	// Set ready condition
	err = r.applyCondition(ctx, &oob, metav1.Condition{
		Type:   "Ready",
		Status: "True",
		Reason: "Ready",
	}, "oob.ironcore.dev/oob")
	if err != nil {
		return ctrl.Result{}, err
	}

	// Apply any changes to the OOB spec
	if specChanged {
		oob = oobv1alpha1.OOB{
			TypeMeta: metav1.TypeMeta{
				APIVersion: oobv1alpha1.GroupVersion.String(),
				Kind:       "OOB",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: oob.Namespace,
				Name:      oob.Name,
			},
			Spec: oobv1alpha1.OOBSpec{
				LocatorLED: oob.Spec.LocatorLED,
				Power:      oob.Spec.Power,
				Reset:      oob.Spec.Reset,
			},
		}

		// Apply the OOB
		log.Info(ctx, "Applying OOB")
		err = r.Patch(ctx, &oob, client.Apply, client.FieldOwner("oob.ironcore.dev/oob"), client.ForceOwnership)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot apply OOB: %w", err)
		}
	}

	log.Debug(ctx, "Reconciled successfully")
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *OOBReconciler) applyErrorCondition(ctx context.Context, oob *oobv1alpha1.OOB, msgErr error) error {
	return r.applyCondition(ctx, oob, metav1.Condition{
		Type:    "Ready",
		Status:  "False",
		Reason:  "Error",
		Message: msgErr.Error(),
	}, "oob.ironcore.dev/oob")
}

func (r *OOBReconciler) applyCondition(ctx context.Context, oob *oobv1alpha1.OOB, cond metav1.Condition, owner client.FieldOwner) error {
	// Set ready condition
	oobNext := &oobv1alpha1.OOB{
		TypeMeta: metav1.TypeMeta{
			APIVersion: oobv1alpha1.GroupVersion.String(),
			Kind:       "OOB",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: oob.Namespace,
			Name:      oob.Name,
		},
		Status: oobv1alpha1.OOBStatus{
			Conditions: condition.SetCondition(oob.Status.Conditions, cond),
		},
	}

	// Apply the OOB status
	log.Info(ctx, "Applying OOB status")
	err := r.Status().Patch(ctx, oobNext, client.Apply, owner, client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply OOB status: %w", err)
	}
	*oob = *oobNext

	return nil
}

func (r *OOBReconciler) clearNoneFields(ctx context.Context, oob *oobv1alpha1.OOB) (bool, error) {
	// Replace all None fields with blanks in order to delete the fields
	// This dance is necessary because one cannot delete a field if there happens to be another owner
	hasTemp := false
	// TODO: Replace unconditionally setting a filler value with this cleanup code when https://github.com/kubernetes/kubernetes/issues/117447 is solved
	//if oob.Spec.Filler != nil {
	//	if *oob.Spec.Filler == 0 {
	//		oob.Spec.Filler = nil
	//		hasTemp = true
	//	} else {
	//		*oob.Spec.Filler = 0
	//		hasTemp = true
	//	}
	//}
	if oob.Spec.LocatorLED == "None" {
		oob.Spec.LocatorLED = ""
		hasTemp = true
	}
	if oob.Spec.Power == "None" {
		oob.Spec.Power = ""
		hasTemp = true
	}
	if oob.Spec.Reset == "None" {
		oob.Spec.Reset = ""
		hasTemp = true
	}
	if !hasTemp {
		return false, nil
	}

	oobNext := &oobv1alpha1.OOB{
		TypeMeta: metav1.TypeMeta{
			APIVersion: oobv1alpha1.GroupVersion.String(),
			Kind:       "OOB",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: oob.Namespace,
			Name:      oob.Name,
		},
		Spec: oobv1alpha1.OOBSpec{
			LocatorLED: oob.Spec.LocatorLED,
			Power:      oob.Spec.Power,
			Reset:      oob.Spec.Reset,
			//Filler:		oob.Spec.Filler, //TODO: see above
			Filler: rand.NewRandInt64(),
		},
	}

	// Apply the OOB
	log.Info(ctx, "Applying OOB")
	err := r.Patch(ctx, oobNext, client.Apply, client.FieldOwner("oob.ironcore.dev/oob"), client.ForceOwnership)
	if err != nil {
		return false, fmt.Errorf("cannot apply OOB: %w", err)
	}
	*oob = *oobNext

	return true, nil
}

func (r *OOBReconciler) ensureGoodCredentials(ctx context.Context, oob *oobv1alpha1.OOB) (bmc.BMC, bool, error, error) {
	// Read the credentials secret if one exists
	creds, exp, msgErr, err := r.getCredentials(ctx, oob)
	if (err != nil && !apierrors.IsNotFound(err)) || msgErr != nil {
		return nil, false, msgErr, err
	}
	expireCreds := false

	// If the OOB is missing basic access data, look it up in the MAC prefix list
	var ai accessInfo
	if oob.Status.Protocol == "" || (creds.Username == "" && creds.Password == "") {
		var ok bool
		ai, ok = r.macPrefixes.get(oob.Status.Mac)

		// Mark the OOB as unknown if no prefix entry exists
		if !ok {
			// Set ready condition
			err = r.applyCondition(ctx, oob, metav1.Condition{
				Type:   "Ready",
				Status: "False",
				Reason: "Unknown",
			}, "oob.ironcore.dev/oob")
			if err != nil {
				return nil, false, nil, err
			}

			return nil, true, nil, nil
		}

		// Mark the OOB as disregarded if indicated in the prefix entry
		if ai.Disregard {
			// Add a disregard annotation
			oobNext := &oobv1alpha1.OOB{
				TypeMeta: metav1.TypeMeta{
					APIVersion: oobv1alpha1.GroupVersion.String(),
					Kind:       "OOB",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace:   oob.Namespace,
					Name:        oob.Name,
					Annotations: map[string]string{"oob.ironcore.dev/disregard": "true"},
				},
			}

			// Apply the OOB
			log.Info(ctx, "Applying OOB")
			err = r.Patch(ctx, oobNext, client.Apply, client.FieldOwner("oob.ironcore.dev/oob"), client.ForceOwnership)
			if err != nil {
				return nil, false, nil, fmt.Errorf("cannot apply OOB: %w", err)
			}
			*oob = *oobNext

			//Set ready condition
			err = r.applyCondition(ctx, oob, metav1.Condition{
				Type:   "Ready",
				Status: "False",
				Reason: "Disregarded",
			}, "oob.ironcore.dev/oob")
			if err != nil {
				return nil, false, nil, err
			}

			return nil, true, nil, nil
		}

		err = r.applyCondition(ctx, oob, metav1.Condition{
			Type:   "Ready",
			Status: "False",
			Reason: "SettingUp",
		}, "oob.ironcore.dev/oob")
		if err != nil {
			return nil, false, nil, err
		}
	}

	// If the protocol is unknown, attempt to determine it
	if oob.Status.Protocol == "" {
		log.Debug(ctx, "Determining OOB protocol")

		// Give up if the protocol cannot be determined
		if ai.Protocol == "" {
			return nil, false, fmt.Errorf("no known way of connecting to the OOB"), nil
		}

		// Construct a new OOB
		oobNext := &oobv1alpha1.OOB{
			TypeMeta: metav1.TypeMeta{
				APIVersion: oobv1alpha1.GroupVersion.String(),
				Kind:       "OOB",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: oob.Namespace,
				Name:      oob.Name,
			},
			Status: oobv1alpha1.OOBStatus{
				Protocol: ai.Protocol,
				Tags:     r.tagsToK8s(ai.Tags),
				Port:     ai.Port,
			},
		}

		// Apply the OOB
		log.Info(ctx, "Applying OOB status")
		err = r.Status().Patch(ctx, oobNext, client.Apply, client.FieldOwner("oob.ironcore.dev/oob/proto"), client.ForceOwnership)
		if err != nil {
			return nil, false, nil, fmt.Errorf("cannot apply OOB status: %w", err)
		}
		*oob = *oobNext
	}
	ctx = log.WithValues(ctx, "proto", oob.Status.Protocol)

	// Initialize BMC
	var tags map[string]string
	tags, err = r.tagMapFromK8s(oob.Status.Tags)
	if err != nil {
		return nil, false, fmt.Errorf("invalid OOB tags: %w", err), nil
	}
	var bmctrl bmc.BMC
	bmctrl, err = bmc.NewBMC(oob.Status.Protocol, tags, oob.Status.IP, oob.Status.Port, creds, exp)
	if err != nil {
		return nil, false, fmt.Errorf("cannot initialize BMC: %w", err), nil
	}

	// If credentials are unknown create new ones, otherwise try connecting
	if creds.Username == "" && creds.Password == "" {
		log.Info(ctx, "Ensuring initial credentials")
		err = bmctrl.EnsureInitialCredentials(ctx, ai.DefaultCredentials, r.temporaryPassword)
		if err != nil {
			return nil, false, fmt.Errorf("cannot ensure initial credentials: %w", err), nil
		}
		expireCreds = true
	} else {
		err = bmctrl.Connect(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("cannot connect to BMC: %w", err), nil
		}
	}

	// If the type had to be determined or the credentials created, expire the credentials to get fresh ones
	now := time.Now()
	if expireCreds {
		exp = now
	}

	// If the credentials have expired (or are initial) create a new set of credentials
	if !exp.IsZero() {
		timeToRenew := exp.Add(-r.credentialsExpBuffer)
		if timeToRenew.Before(now) {
			log.Info(ctx, "Creating new credentials", "expired", exp)

			// Create new credentials
			err = r.createCredentials(ctx, bmctrl)
			if err != nil {
				return nil, false, fmt.Errorf("cannot create new credentials: %w", err), nil
			}
			creds, exp = bmctrl.Credentials()
			if exp.IsZero() {
				exp = time.Now().AddDate(0, 0, 30)
			}
			ctx = log.WithValues(ctx, "expiration", exp)

			// Persist the new credentials in case any upcoming operations fail
			err = r.persistCredentials(ctx, oob, creds, exp)
			if err != nil {
				return nil, false, fmt.Errorf("cannot persist BMC credentials: %w", err), nil
			}

			// Delete obsolete credentials
			err = bmctrl.DeleteUsers(ctx, r.usernameRegex)
			if err != nil {
				return nil, false, fmt.Errorf("cannot delete obsolete credentials: %w", err), nil
			}
		}
	}

	return bmctrl, false, nil, nil
}

func (r *OOBReconciler) getCredentials(ctx context.Context, oob *oobv1alpha1.OOB) (bmc.Credentials, time.Time, error, error) {
	if oob.Status.Mac == "" {
		return bmc.Credentials{}, time.Time{}, fmt.Errorf("OOB has no MAC address"), nil
	}

	// Get the secret
	secret := &corev1.Secret{}
	err := r.Get(ctx, client.ObjectKey{Namespace: oob.Namespace, Name: oob.Status.Mac}, secret)
	if err != nil {
		return bmc.Credentials{}, time.Time{}, nil, fmt.Errorf("cannot get credentials secret: %w", err)
	}

	// Validate the secret
	if secret.Type != "kubernetes.io/basic-auth" {
		return bmc.Credentials{}, time.Time{}, fmt.Errorf("credentials secret has incorrect type: %s", secret.Type), nil
	}

	// Extract and verify fields
	var mac, username, passwd, expStr []byte
	var ok bool
	mac, ok = secret.Data["mac"]
	if !ok {
		return bmc.Credentials{}, time.Time{}, fmt.Errorf("credentials secret does not contain a MAC address"), nil
	}
	if string(mac) != oob.Status.Mac {
		return bmc.Credentials{}, time.Time{}, fmt.Errorf("credentials secret has an unexpected MAC address: %s", mac), nil
	}
	username, ok = secret.Data["username"]
	if !ok {
		return bmc.Credentials{}, time.Time{}, fmt.Errorf("credentials secret does not contain a username"), nil
	}
	passwd, ok = secret.Data["password"]
	if !ok {
		return bmc.Credentials{}, time.Time{}, fmt.Errorf("credentials secret does not contain a password"), nil
	}
	exp := time.Time{}
	expStr, ok = secret.Data["expiration"]
	if ok {
		err = exp.UnmarshalText(expStr)
		if err != nil {
			return bmc.Credentials{}, time.Time{}, fmt.Errorf("credentials secret contains an invalid expiration time: %w", err), nil
		}
	}

	return bmc.Credentials{Username: string(username), Password: string(passwd)}, exp, nil, nil
}

func (r *OOBReconciler) tagMapFromK8s(tags []oobv1alpha1.TagSpec) (map[string]string, error) {
	tmap := make(map[string]string)
	for _, t := range tags {
		_, ok := tmap[t.Key]
		if ok {
			return nil, fmt.Errorf("tag keys must be unique: %s", t.Key)
		}
		tmap[t.Key] = t.Value
	}
	return tmap, nil
}

func (r *OOBReconciler) tagsToK8s(tags []tag) []oobv1alpha1.TagSpec {
	var k8sTags []oobv1alpha1.TagSpec
	for _, t := range tags {
		k8sTags = append(k8sTags, oobv1alpha1.TagSpec{Key: t.Key, Value: t.Value})
	}
	return k8sTags
}

func (r *OOBReconciler) createCredentials(ctx context.Context, bmctrl bmc.BMC) error {
	// Generate credentials
	var creds bmc.Credentials
	creds.Username = r.usernamePrefix + password.MustGenerate(6, 0, 0, true, false)
	creds.Password = password.MustGenerate(16, 6, 0, false, true)

	// Generate a second password to be used in case of a password change requirement
	anotherPassword := password.MustGenerate(16, 6, 0, false, true)

	// Use the existing credentials to create a new user with a new password
	err := bmctrl.CreateUser(ctx, creds, anotherPassword)
	if err != nil {
		return fmt.Errorf("cannot create user: %w", err)
	}

	return nil
}

func (r *OOBReconciler) persistCredentials(ctx context.Context, oob *oobv1alpha1.OOB, creds bmc.Credentials, exp time.Time) error {
	if oob.Status.Mac == "" {
		return fmt.Errorf("OOB has no MAC address")
	}

	// Construct a new secret
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      oob.Status.Mac,
			Namespace: oob.Namespace,
		},
		Type: "kubernetes.io/basic-auth",
		StringData: map[string]string{
			"mac":      oob.Status.Mac,
			"username": creds.Username,
			"password": creds.Password,
		},
	}
	if !exp.IsZero() {
		expStr, err := exp.MarshalText()
		if err != nil {
			return fmt.Errorf("cannot marshal expiration time: %w", err)
		}
		secret.StringData["expiration"] = string(expStr)
	}

	// Apply the secret
	log.Info(ctx, "Applying credentials secret")
	err := r.Patch(ctx, secret, client.Apply, client.FieldOwner("oob.ironcore.dev/creds"), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply secret: %w", err)
	}

	return nil
}

func (r *OOBReconciler) ensureCorrectUUIDandName(ctx context.Context, oob *oobv1alpha1.OOB, uuid string) (bool, error) {
	// If the UUID changed, remove any preexisting BMCs with the same UUID
	if oob.Status.UUID != uuid {
		// Find any existing OOB with the same UUID
		existingOob, err := r.ensureUniqueOOBByUUID(ctx, oob.Namespace, uuid)
		if err != nil {
			return false, err
		}

		// Adopt any existing OOB's spec into the new OOB
		if existingOob != nil {
			// Set ready condition
			err = r.applyCondition(ctx, oob, metav1.Condition{
				Type:   "Ready",
				Status: "False",
				Reason: "AdoptedSpec",
			}, "oob.ironcore.dev/oob")
			if err != nil {
				return false, err
			}

			// Construct a new OOB
			oobNext := &oobv1alpha1.OOB{
				TypeMeta: metav1.TypeMeta{
					APIVersion: oobv1alpha1.GroupVersion.String(),
					Kind:       "OOB",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: oob.Namespace,
					Name:      oob.Name,
				},
				Spec: existingOob.Spec,
			}

			// Adopt the spec of the existing OOB and delete it
			log.Info(ctx, "Adopting spec of existing OOB with the same UUID", "existingOob", existingOob.Name)
			err = r.Delete(ctx, existingOob)
			if err != nil {
				return false, fmt.Errorf("cannot delete OOB: %w", err)
			}
			gen := oob.Generation
			log.Info(ctx, "Applying OOB")
			err = r.Patch(ctx, oobNext, client.Apply, client.FieldOwner("oob.ironcore.dev/oob"), client.ForceOwnership)
			if err != nil {
				return false, fmt.Errorf("cannot apply OOB: %w", err)
			}
			*oob = *oobNext
			if oob.Generation != gen {
				return true, nil
			}
		}

		// Construct a new OOB
		oobNext := &oobv1alpha1.OOB{
			TypeMeta: metav1.TypeMeta{
				APIVersion: oobv1alpha1.GroupVersion.String(),
				Kind:       "OOB",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: oob.Namespace,
				Name:      oob.Name,
			},
			Status: oobv1alpha1.OOBStatus{
				UUID: uuid,
			},
		}

		// Apply the OOB
		log.Info(ctx, "Applying OOB status")
		err = r.Status().Patch(ctx, oobNext, client.Apply, client.FieldOwner("oob.ironcore.dev/oob/uuid"), client.ForceOwnership)
		if err != nil {
			return false, fmt.Errorf("cannot apply OOB status: %w", err)
		}
		*oob = *oobNext

		// Set ready condition
		err = r.applyCondition(ctx, oob, metav1.Condition{
			Type:   "Ready",
			Status: "False",
			Reason: "NewUUID",
		}, "oob.ironcore.dev/oob")
		if err != nil {
			return false, err
		}
	}
	ctx = log.WithValues(ctx, "uuid", oob.Status.UUID)

	// If the name does not match the UUID, replace the BMC with a new BMC with the correct name
	name := oob.Status.UUID
	if oob.Name != name {
		// Set ready condition
		err := r.applyCondition(ctx, oob, metav1.Condition{
			Type:   "Ready",
			Status: "False",
			Reason: "ToBeReplaced",
		}, "oob.ironcore.dev/oob")
		if err != nil {
			return false, err
		}

		// Replace OOB in order to rename it
		err = r.replaceOOB(ctx, oob, name)
		if err != nil {
			return false, fmt.Errorf("cannot replace OOB: %w", err)
		}

		return true, nil
	}

	return false, nil
}

func (r *OOBReconciler) ensureUniqueOOBByUUID(ctx context.Context, namespace, uuid string) (*oobv1alpha1.OOB, error) {
	// Get all OOBss with a given UUID
	var oobs oobv1alpha1.OOBList
	err := r.List(ctx, &oobs, client.InNamespace(namespace), client.MatchingFields{".status.uuid": uuid})
	if err != nil {
		return nil, fmt.Errorf("cannot list existing OOBs with UUID %s: %w", uuid, err)
	}
	if len(oobs.Items) == 0 {
		return nil, nil
	}

	// If any OOBs are found, delete all but the newest
	newest := 0
	if len(oobs.Items) > 1 {
		del := make([]int, 0, len(oobs.Items)-1)
		for i := 1; i < len(oobs.Items); i += 1 {
			if oobs.Items[i].CreationTimestamp.Before(&oobs.Items[newest].CreationTimestamp) {
				del = append(del, i)
			} else {
				del = append(del, newest)
				newest = i
			}
		}
		for _, i := range del {
			log.Info(ctx, "Deleting older OOB with the same UUID", "oob", &oobs.Items[i].Name, "ns", &oobs.Items[i].Namespace)
			err = r.Delete(ctx, &oobs.Items[i])
			if err != nil {
				return nil, fmt.Errorf("cannot delete OOB: %w", err)
			}
		}
	}
	return &oobs.Items[newest], nil
}

func (r *OOBReconciler) replaceOOB(ctx context.Context, oob *oobv1alpha1.OOB, name string) error {
	// Delete the obsolete OOB
	log.Info(ctx, "Deleting OOB")
	err := r.Delete(ctx, oob)
	if err != nil {
		return fmt.Errorf("cannot delete OOB: %w", err)
	}

	// Construct a new OOB
	// The oob-ignore annotation prevents reconciling
	oobRepl := &oobv1alpha1.OOB{
		TypeMeta: metav1.TypeMeta{
			APIVersion: oobv1alpha1.GroupVersion.String(),
			Kind:       "OOB",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   oob.Namespace,
			Name:        name,
			Annotations: map[string]string{"oob.ironcore.dev/ignore": "true"},
		},
	}
	oob.Spec.DeepCopyInto(&oobRepl.Spec)
	ctx = log.WithValues(ctx, "newName", oobRepl.Name)

	// Apply the new OOB
	log.Info(ctx, "Applying OOB under its correct name")
	err = r.Patch(ctx, oobRepl, client.Apply, client.FieldOwner("oob.ironcore.dev/oob"), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply OOB: %w", err)
	}

	// Create a status patch
	oobRepl = &oobv1alpha1.OOB{
		TypeMeta: metav1.TypeMeta{
			APIVersion: oobv1alpha1.GroupVersion.String(),
			Kind:       "OOB",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: oob.Namespace,
			Name:      name,
		},
	}
	oob.Status.DeepCopyInto(&oobRepl.Status)

	// Apply the status
	log.Info(ctx, "Applying OOB status")
	err = r.Status().Patch(ctx, oobRepl, client.Apply, client.FieldOwner("oob.ironcore.dev/oob"), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply OOB status: %w", err)
	}

	// Restore the correct managedFields
	log.Info(ctx, "Patching OOB")
	oobPatch := oobRepl.DeepCopy()
	oobPatch.ManagedFields = append(oob.ManagedFields, metav1.ManagedFieldsEntry{
		Manager:    "oob.ironcore.dev/oob",
		Operation:  "Apply",
		APIVersion: oobv1alpha1.GroupVersion.String(),
		Time: &metav1.Time{
			Time: time.Now(),
		},
		FieldsType: "FieldsV1",
		FieldsV1: &metav1.FieldsV1{
			Raw: []byte(`{"f:metadata":{"f:annotations":{"f:oob.ironcore.dev/ignore":{}}}}`),
		},
	})
	err = r.Patch(ctx, oobPatch, client.MergeFrom(oobRepl))
	if err != nil {
		return fmt.Errorf("cannot patch OOB: %w", err)
	}

	// Set ready condition
	err = r.applyCondition(ctx, oobRepl, metav1.Condition{
		Type:   "Ready",
		Status: "False",
		Reason: "SettingUp",
	}, "oob.ironcore.dev/oob")
	if err != nil {
		return err
	}

	// Remove the ignore annotation and force a reconciliation
	oobRepl = &oobv1alpha1.OOB{
		TypeMeta: metav1.TypeMeta{
			APIVersion: oobv1alpha1.GroupVersion.String(),
			Kind:       "OOB",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: oob.Namespace,
			Name:      name,
		},
		Spec: oobv1alpha1.OOBSpec{
			Filler: rand.NewRandInt64(),
		},
	}

	// Apply the new OOB
	log.Info(ctx, "Applying OOB")
	err = r.Patch(ctx, oobRepl, client.Apply, client.FieldOwner("oob.ironcore.dev/oob"), client.ForceOwnership)
	if err != nil {
		return fmt.Errorf("cannot apply OOB: %w", err)
	}

	return nil
}

func (r *OOBReconciler) setNTPServers(ctx context.Context, bmctrl bmc.BMC) error {
	ntpc, ok := bmctrl.(bmc.NTPControl)
	if ok {
		err := ntpc.SetNTPServers(ctx, r.ntpServers)
		if err != nil {
			return fmt.Errorf("cannot set NTP servers: %w", err)
		}
	}

	return nil
}

func (r *OOBReconciler) setStatusFields(oob *oobv1alpha1.OOB, info *bmc.Info, requeueAfter *time.Duration) bool {
	statusChanged := false

	// Fill in all non-modifiable fields
	if oob.Status.Type != info.Type || !slices.Equal(oob.Status.Capabilities, info.Capabilities) || oob.Status.Manufacturer != info.Manufacturer || oob.Status.SerialNumber != info.SerialNumber || oob.Status.SKU != info.SKU || oob.Status.Console != info.Console || oob.Status.FWVersion != info.FWVersion {
		oob.Status.Type = info.Type
		oob.Status.Capabilities = info.Capabilities
		oob.Status.Manufacturer = info.Manufacturer
		oob.Status.SKU = info.SKU
		oob.Status.SerialNumber = info.SerialNumber
		oob.Status.Console = info.Console
		oob.Status.FWVersion = info.FWVersion
		statusChanged = true
	}

	// Update the status fields to their actual state
	if oob.Status.LocatorLED != info.LocatorLED || oob.Status.Power != info.Power || oob.Status.OSReason != info.OSReason {
		oob.Status.LocatorLED = info.LocatorLED
		oob.Status.Power = info.Power
		oob.Status.OSReason = info.OSReason
		statusChanged = true
	}

	now := metav1.Now()

	// If the machine is Off, clear OS status and all deadlines
	if info.Power == "Off" {
		if oob.Status.OS != "" {
			oob.Status.OS = ""
			statusChanged = true
		}
		if oob.Status.OSReadDeadline != nil {
			oob.Status.OSReadDeadline = nil
			statusChanged = true
		}
		if oob.Status.ShutdownDeadline != nil {
			oob.Status.ShutdownDeadline = nil
			statusChanged = true
		}
		return statusChanged
	}

	// If we don't support reading the OS state, clear all OS related fields, if they are set to anything
	if info.OSReason == "" {
		if oob.Status.OS != "" || oob.Status.OSReadDeadline != nil {
			oob.Status.OS = ""
			oob.Status.OSReadDeadline = nil
			statusChanged = true
		}
		return statusChanged
	}

	// If the OS is Ok, clear OS read deadline
	if info.OS == "Ok" {
		if oob.Status.OS != "Ok" {
			oob.Status.OS = "Ok"
			statusChanged = true
		}
		if oob.Status.OSReadDeadline != nil {
			oob.Status.OSReadDeadline = nil
			statusChanged = true
		}
		return statusChanged
	}

	// If there is a deadline and it has expired, set OS to TimedOut and clear the deadline
	if !oob.Status.OSReadDeadline.IsZero() && oob.Status.OSReadDeadline.Before(&now) {
		if oob.Status.OS != "TimedOut" {
			oob.Status.OS = "TimedOut"
		}
		oob.Status.OSReadDeadline = nil
		return true
	}

	// If the OS has timed out, clear the deadline
	if oob.Status.OS == "TimedOut" {
		if oob.Status.OSReadDeadline != nil {
			oob.Status.OSReadDeadline = nil
			statusChanged = true
		}
		return statusChanged
	}

	// Set OS to Waiting and set a deadline
	if oob.Status.OS != "Waiting" {
		oob.Status.OS = "Waiting"
		statusChanged = true
	}
	if oob.Status.OSReadDeadline.IsZero() {
		oob.Status.OSReadDeadline = &metav1.Time{Time: now.Add(7 * time.Minute)}
		statusChanged = true
	}

	// Reconcile again after a short time to update the status
	*requeueAfter = time.Second * 3

	return statusChanged
}

func (r *OOBReconciler) applyLocatorLED(ctx context.Context, oob *oobv1alpha1.OOB, bmctrl bmc.BMC, specChanged, statusChanged *bool) error {
	// If no change is requested or necessary, return
	if oob.Spec.LocatorLED == "" || oob.Spec.LocatorLED == "None" || oob.Spec.LocatorLED == oob.Status.LocatorLED {
		return nil
	}

	// If LED control is not supported, clear the request
	lc, ok := bmctrl.(bmc.LEDControl)
	if !ok {
		log.Info(ctx, "LED control is not supported")
		oob.Spec.LocatorLED = "None"
		*specChanged = true
		return nil
	}

	// Perform the change
	var err error
	oob.Status.LocatorLED, err = lc.SetLocatorLED(ctx, oob.Spec.LocatorLED)
	if err != nil {
		return fmt.Errorf("cannot set locator LED to %s: %w", oob.Spec.LocatorLED, err)
	}
	*statusChanged = true

	return nil
}

func (r *OOBReconciler) applyPower(ctx context.Context, oob *oobv1alpha1.OOB, bmctrl bmc.BMC, specChanged, statusChanged *bool, requeueAfter *time.Duration) error {
	// If no change is requested, return
	if oob.Spec.Power == "" || oob.Spec.Power == "None" {
		return nil
	}

	// If power control is not supported, clear the request
	pc, ok := bmctrl.(bmc.PowerControl)
	if !ok {
		log.Info(ctx, "Power control is not supported")
		oob.Spec.Power = "None"
		*specChanged = true
		if oob.Status.ShutdownDeadline != nil {
			oob.Status.ShutdownDeadline = nil
			*statusChanged = true
		}
		return nil
	}

	// If a power change is requested, the action depends on both the request and the current state
	switch oob.Spec.Power {

	case "On":
		switch oob.Status.Power {
		case "On":
			// On -> On: noop

		case "Off":
			// Off -> On: turn the machine on
			err := pc.PowerOn(ctx)
			if err != nil {
				return fmt.Errorf("cannot power on machine: %w", err)
			}

			// Clear the shutdown deadline because the machine is not shutting down
			if oob.Status.ShutdownDeadline != nil {
				oob.Status.ShutdownDeadline = nil
				*statusChanged = true
			}

			// Reset OS status and the OS read deadline
			if oob.Status.OS != "" {
				oob.Status.OS = ""
				*statusChanged = true
			}
			if oob.Status.OSReadDeadline != nil {
				oob.Status.OSReadDeadline = nil
				*statusChanged = true
			}

			// Reconcile again after a short time to update the status
			*requeueAfter = time.Second * 3

		default:
			return fmt.Errorf("unsupported current power state %s", oob.Status.Power)
		}

	case "Off":
		switch oob.Status.Power {

		case "On":
			now := metav1.Now()

			// On -> Off: turn the machine off if it's not already shutting down, turn it off forcefully if the deadline has expired, or do nothing if it is already shutting down
			if oob.Status.ShutdownDeadline.IsZero() {
				err := pc.PowerOff(ctx, false)
				if err != nil {
					return fmt.Errorf("cannot power off machine: %w", err)
				}
				oob.Status.ShutdownDeadline = &metav1.Time{Time: now.Add(r.shutdownTimeout)}
				*statusChanged = true
			} else if oob.Status.ShutdownDeadline.Before(&now) {
				log.Info(ctx, "Shutdown deadline exceeded, shutting down forcefully")
				err := pc.PowerOff(ctx, true)
				if err != nil {
					return fmt.Errorf("cannot power off machine: %w", err)
				}
				oob.Status.ShutdownDeadline = nil
				*statusChanged = true
			}
			*requeueAfter = time.Second * 3

		case "Off":
			// Off -> Off: noop
			// Clear the shutdown deadline because the machine is not shutting down
			if oob.Status.ShutdownDeadline != nil {
				oob.Status.ShutdownDeadline = nil
				*statusChanged = true
			}

		default:
			return fmt.Errorf("unsupported requested power state %s", oob.Spec.Power)
		}

		// Clear any Reset
		if oob.Spec.Reset != "" {
			oob.Spec.Reset = "None"
			*specChanged = true
		}

	case "OffImmediate":
		switch oob.Status.Power {
		case "On":
			// On -> OffImmediate: turn the machine off forcefully and reconcile again after a short time to update the status
			err := pc.PowerOff(ctx, true)
			if err != nil {
				return fmt.Errorf("cannot power off machine: %w", err)
			}
			*requeueAfter = time.Second * 3

		case "Off":
			// Off -> OffImmediate: set the machine to off

		default:
			return fmt.Errorf("unsupported power state %s", oob.Status.Power)
		}

		oob.Spec.Power = "Off"
		*specChanged = true

		// Clear the shutdown deadline because the machine is not shutting down
		if oob.Status.ShutdownDeadline != nil {
			oob.Status.ShutdownDeadline = nil
			*statusChanged = true
		}

		// Clear any Reset
		if oob.Spec.Reset != "" {
			oob.Spec.Reset = "None"
			*specChanged = true
		}

	default:
		return fmt.Errorf("unsupported power state %s", oob.Spec.Power)
	}

	return nil
}

func (r *OOBReconciler) applyReset(ctx context.Context, oob *oobv1alpha1.OOB, bmctrl bmc.BMC, specChanged, statusChanged *bool, requeueAfter *time.Duration) error {
	// If no change is requested, return
	if oob.Spec.Reset == "" || oob.Spec.Reset == "None" {
		return nil
	}

	// If power control is not supported, clear the request
	rc, ok := bmctrl.(bmc.ResetControl)
	if !ok {
		log.Info(ctx, "Reset control is not supported")
		oob.Spec.Reset = "None"
		*specChanged = true
		return nil
	}

	// If the machine is not on, clear the request and do nothing
	if oob.Status.Power != "On" {
		oob.Spec.Reset = "None"
		*specChanged = true
		return nil
	}

	// If a reset is requested, the action depends on both the request and the current power state
	switch oob.Spec.Reset {

	case "Reset":
		// Reset the machine
		err := rc.Reset(ctx, false)
		if err != nil {
			return fmt.Errorf("cannot reset machine: %w", err)
		}

	case "ResetImmediate":
		// Reset the machine forcefully
		err := rc.Reset(ctx, true)
		if err != nil {
			return fmt.Errorf("cannot reset machine: %w", err)
		}

	default:
		return fmt.Errorf("unsupported reset state %s", oob.Spec.Reset)
	}

	// Clear the reset
	oob.Spec.Reset = "None"
	*specChanged = true

	// Clear the shutdown deadline
	if oob.Status.ShutdownDeadline != nil {
		oob.Status.ShutdownDeadline = nil
		*statusChanged = true
	}

	// Reset OS status and the OS read deadline
	if oob.Status.OS != "" {
		oob.Status.OS = ""
		*statusChanged = true
	}
	if oob.Status.OSReadDeadline != nil {
		oob.Status.OSReadDeadline = nil
		*statusChanged = true
	}

	// Reconcile again after a short time to update the status
	*requeueAfter = time.Second * 3

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *OOBReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Client = mgr.GetClient()

	err := mgr.GetFieldIndexer().IndexField(context.Background(), &oobv1alpha1.OOB{}, ".status.uuid", func(obj client.Object) []string {
		oob := obj.(*oobv1alpha1.OOB)
		if oob.Status.UUID == "" {
			return nil
		}
		return []string{oob.Status.UUID}
	})
	if err != nil {
		return err
	}

	inCorrectNamespacePredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return r.namespace == "" || e.Object.GetNamespace() == r.namespace
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return r.namespace == "" || e.ObjectNew.GetNamespace() == r.namespace
		},
	}

	notBeingDeletedPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return e.Object.GetDeletionTimestamp().IsZero()
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return e.ObjectNew.GetDeletionTimestamp().IsZero()
		},
	}

	notIgnoredPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			ignore, ok := e.Object.GetAnnotations()["oob.ironcore.dev/ignore"]
			return !(ok && ignore == "true")
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			ignore, ok := e.ObjectNew.GetAnnotations()["oob.ironcore.dev/ignore"]
			return !(ok && ignore == "true")
		},
	}

	notDisregardedPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			disregard, ok := e.Object.GetAnnotations()["oob.ironcore.dev/disregard"]
			return !(ok && disregard == "true")
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			disregard, ok := e.ObjectNew.GetAnnotations()["oob.ironcore.dev/disregard"]
			return !(ok && disregard == "true")
		},
	}

	return ctrl.NewControllerManagedBy(mgr).For(&oobv1alpha1.OOB{}).WithEventFilter(predicate.And(predicate.GenerationChangedPredicate{}, inCorrectNamespacePredicate, notBeingDeletedPredicate, notIgnoredPredicate, notDisregardedPredicate)).WithOptions(controller.Options{MaxConcurrentReconciles: 10}).Complete(r)
}
