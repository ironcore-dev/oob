// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package controllers

import (
	"context"
	"fmt"
	"regexp"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	ipamv1alpha1 "github.com/ironcore-dev/ipam/api/ipam/v1alpha1"
	oobv1alpha1 "github.com/ironcore-dev/oob/api/v1alpha1"
	"github.com/ironcore-dev/oob/internal/condition"
	"github.com/ironcore-dev/oob/internal/log"
	"github.com/ironcore-dev/oob/internal/rand"
)

//+kubebuilder:rbac:groups=ipam.metal.ironcore.dev,resources=ips,verbs=get;list;watch
//+kubebuilder:rbac:groups=ipam.metal.ironcore.dev,resources=ips/status,verbs=get

func NewIPReconciler(namespace string, subnetLabelName string, subnetLabelValue string) (*IPReconciler, error) {
	return &IPReconciler{
		namespace:        namespace,
		subnetLabelName:  subnetLabelName,
		subnetLabelValue: subnetLabelValue,
	}, nil
}

// IPReconciler reconciles a IP object.
type IPReconciler struct {
	client.Client
	namespace        string
	subnetLabelName  string
	subnetLabelValue string
	disabled         bool
	disabledMtx      sync.RWMutex
	macRegex         *regexp.Regexp
}

func (r *IPReconciler) enable() {
	r.disabledMtx.Lock()
	defer r.disabledMtx.Unlock()
	r.disabled = false
}

func (r *IPReconciler) disable() {
	r.disabledMtx.Lock()
	defer r.disabledMtx.Unlock()
	r.disabled = true
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *IPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.disabledMtx.RLock()
	defer r.disabledMtx.RUnlock()
	if r.disabled {
		return ctrl.Result{}, nil
	}

	return r.reconcile(ctx, req)
}

func (r *IPReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ip ipamv1alpha1.IP
	err := r.Get(ctx, req.NamespacedName, &ip)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get IP: %w", err))
	}

	ctx = log.WithValues(ctx, "ip", ip.Spec.IP.String())
	log.Debug(ctx, "Reconciling")

	// Get the MAC address from the DHCP lease
	mac, ok := ip.Labels["mac"]
	if !ok {
		log.Debug(ctx, "Missing MAC address, ignoring lease")
		return ctrl.Result{}, nil
	}
	if !r.macRegex.MatchString(mac) {
		return ctrl.Result{}, fmt.Errorf("invalid MAC address: %s", mac)
	}
	ctx = log.WithValues(ctx, "mac", mac)

	// Find an existing OOB if there is one
	var oob *oobv1alpha1.OOB
	oob, err = r.ensureUniqueOOBByMac(ctx, ip.Namespace, mac)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Do nothing if the IP is already correct
	if oob != nil && oob.Status.IP == ip.Spec.IP.String() {
		log.Debug(ctx, "OOB exists and has the same IP, doing nothing")
		log.Debug(ctx, "Reconciled successfully")
		return ctrl.Result{}, nil
	}

	// Create a new OOB if necessary
	if oob == nil {
		oob = &oobv1alpha1.OOB{
			TypeMeta: metav1.TypeMeta{
				APIVersion: oobv1alpha1.GroupVersion.String(),
				Kind:       "OOB",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ip.Namespace,
				Name:      fmt.Sprintf("mac-%s", mac),
			},
		}

		// Apply the OOB
		log.Info(ctx, "Applying OOB")
		err = r.Patch(ctx, oob, client.Apply, client.FieldOwner("oob.ironcore.dev/ip"), client.ForceOwnership)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("cannot apply OOB: %w", err)
		}
	}
	ctx = log.WithValues(ctx, "oob", oob.Name)

	// Create a status patch
	oob = &oobv1alpha1.OOB{
		TypeMeta: metav1.TypeMeta{
			APIVersion: oobv1alpha1.GroupVersion.String(),
			Kind:       "OOB",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: oob.Namespace,
			Name:      oob.Name,
		},
		Status: oobv1alpha1.OOBStatus{
			IP:  ip.Spec.IP.String(),
			Mac: mac,
			Conditions: condition.SetCondition(oob.Status.Conditions, metav1.Condition{
				Type:   "Ready",
				Status: "False",
				Reason: "NewIP",
			}),
		},
	}

	// Apply the OOB status
	log.Info(ctx, "Applying OOB status")
	err = r.Status().Patch(ctx, oob, client.Apply, client.FieldOwner("oob.ironcore.dev/ip"), client.ForceOwnership)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("cannot apply OOB status: %w", err)
	}

	// Force a reconciliation
	oob = &oobv1alpha1.OOB{
		TypeMeta: metav1.TypeMeta{
			APIVersion: oobv1alpha1.GroupVersion.String(),
			Kind:       "OOB",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: oob.Namespace,
			Name:      oob.Name,
		},
		Spec: oobv1alpha1.OOBSpec{
			Filler: rand.NewRandInt64(),
		},
	}

	// Apply the OOB
	log.Info(ctx, "Applying OOB")
	err = r.Patch(ctx, oob, client.Apply, client.FieldOwner("oob.ironcore.dev/ip"), client.ForceOwnership)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("cannot apply OOB status: %w", err)
	}

	log.Debug(ctx, "Reconciled successfully")
	return ctrl.Result{}, nil
}

func (r *IPReconciler) ensureUniqueOOBByMac(ctx context.Context, namespace, mac string) (*oobv1alpha1.OOB, error) {
	// Get all OOBs with a given MAC
	var oobs oobv1alpha1.OOBList
	err := r.List(ctx, &oobs, client.InNamespace(namespace), client.MatchingFields{".status.mac": mac})
	if err != nil {
		return nil, fmt.Errorf("cannot list existing OOBs with MAC %s: %w", mac, err)
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
			log.Info(ctx, "Deleting older OOB with the same MAC", "oob", &oobs.Items[i].Name, "ns", &oobs.Items[i].Namespace)
			err = r.Delete(ctx, &oobs.Items[i])
			if err != nil {
				return nil, fmt.Errorf("cannot delete OOB: %w", err)
			}
		}
	}
	return &oobs.Items[newest], nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *IPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.macRegex = regexp.MustCompile(`^[0-9A-Fa-f]{12}$`)
	r.Client = mgr.GetClient()

	err := mgr.GetFieldIndexer().IndexField(context.Background(), &oobv1alpha1.OOB{}, ".status.mac", func(obj client.Object) []string {
		oob := obj.(*oobv1alpha1.OOB)
		if oob.Status.Mac == "" {
			return nil
		}
		return []string{oob.Status.Mac}
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

	validPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			ip, ok := e.Object.(*ipamv1alpha1.IP)
			return ok && ip.Spec.IP != nil
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			ip, ok := e.ObjectNew.(*ipamv1alpha1.IP)
			return ok && ip.Spec.IP != nil
		},
	}

	hasValidLabelPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			if r.subnetLabelName != "" {
				l, ok := e.Object.GetLabels()[r.subnetLabelName]
				return ok && l == r.subnetLabelValue
			}
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			if r.subnetLabelName != "" {
				l, ok := e.ObjectNew.GetLabels()[r.subnetLabelName]
				return ok && l == r.subnetLabelValue
			}
			return true
		},
	}

	return ctrl.NewControllerManagedBy(mgr).For(&ipamv1alpha1.IP{}).WithEventFilter(predicate.And(predicate.GenerationChangedPredicate{}, inCorrectNamespacePredicate, notBeingDeletedPredicate, validPredicate, hasValidLabelPredicate)).WithOptions(controller.Options{MaxConcurrentReconciles: 10}).Complete(r)
}
