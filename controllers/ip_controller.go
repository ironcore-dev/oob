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

package controllers

import (
	"context"
	"fmt"
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	ipamv1alpha1 "github.com/onmetal/ipam/api/v1alpha1"
	oobv1alpha1 "github.com/onmetal/oob-operator/api/v1alpha1"
	"github.com/onmetal/oob-operator/log"
)

//+kubebuilder:rbac:groups=ipam.onmetal.de,resources=ips,verbs=get;list;watch
//+kubebuilder:rbac:groups=ipam.onmetal.de,resources=ips/status,verbs=get

// IPReconciler reconciles a IP object.
type IPReconciler struct {
	client.Client
	Namespace string
	macRegex  *regexp.Regexp
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *IPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ip ipamv1alpha1.IP
	err := r.Get(ctx, req.NamespacedName, &ip)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get IP: %w", err))
	}

	return r.reconcile(ctx, &ip)
}

func (r *IPReconciler) reconcile(ctx context.Context, ip *ipamv1alpha1.IP) (ctrl.Result, error) {
	ctx = log.WithValues(ctx, "ip", ip.Spec.IP.String())
	log.Debug(ctx, "Reconciling")

	// Get the MAC address from the DHCP lease
	mac, ok := ip.Labels["mac"]
	if !ok {
		log.Debug(ctx, "Ignoring lease: missing MAC address")
		return ctrl.Result{}, nil
	}
	if !r.macRegex.MatchString(mac) {
		return ctrl.Result{}, fmt.Errorf("invalid MAC address: %s", mac)
	}
	ctx = log.WithValues(ctx, "mac", mac)

	// Find an existing OOB if there is one
	oob, err := r.ensureUniqueOOBByMac(ctx, ip.Namespace, mac)
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
		err = r.Patch(ctx, oob, client.Apply, client.FieldOwner("oob-operator.onmetal.de/ip"), client.ForceOwnership)
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
		},
	}

	// Apply the OOB status
	log.Info(ctx, "Applying OOB")
	err = r.Status().Patch(ctx, oob, client.Apply, client.FieldOwner("oob-operator.onmetal.de/ip"), client.ForceOwnership)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("cannot apply OOB status: %w", err)
	}

	log.Debug(ctx, "Reconciled successfully")
	return ctrl.Result{}, nil
}

func (r *IPReconciler) ensureUniqueOOBByMac(ctx context.Context, namespace, mac string) (*oobv1alpha1.OOB, error) {
	// Get all OOBss with a given MAC
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
			return r.Namespace == "" || e.Object.GetNamespace() == r.Namespace
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return r.Namespace == "" || e.ObjectNew.GetNamespace() == r.Namespace
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

	return ctrl.NewControllerManagedBy(mgr).For(&ipamv1alpha1.IP{}).WithEventFilter(predicate.And(inCorrectNamespacePredicate, notBeingDeletedPredicate)).WithOptions(controller.Options{MaxConcurrentReconciles: 10}).Complete(r)
}
