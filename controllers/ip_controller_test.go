package controllers

import (
	"net/netip"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/onmetal/ipam/api/v1alpha1"
	oobv1alpha1 "github.com/onmetal/oob-operator/api/v1alpha1"
)

var _ = Describe("IP controller", func() {
	var ns string
	BeforeEach(func(ctx SpecContext) {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "testns-"},
		}
		Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
		ns = namespace.Name
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, namespace)).To(Succeed())
		})

		ipReconciler.enable()
		oobReconciler.disable()
	})

	var ip *ipamv1alpha1.IP
	var res reconcile.Result
	var err error
	BeforeEach(func() {
		ip = &ipamv1alpha1.IP{
			TypeMeta: metav1.TypeMeta{
				APIVersion: ipamv1alpha1.GroupVersion.String(),
				Kind:       "IP",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      "ip",
				Labels: map[string]string{
					"mac": "012345abcdef",
				},
			},
			Spec: ipamv1alpha1.IPSpec{
				IP: &ipamv1alpha1.IPAddr{
					Net: netip.MustParseAddr("1.2.3.4"),
				},
			},
		}
		res = reconcile.Result{}
		err = nil
	})

	JustBeforeEach(func(ctx SpecContext) {
		Expect(k8sClient.Patch(ctx, ip, client.Apply, client.FieldOwner("test"), client.ForceOwnership)).To(Succeed())
		Eventually(func(g Gomega, ctx SpecContext) {
			var obj ipamv1alpha1.IP
			g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "ip"}, &obj)).To(Succeed())
		}, ctx, "3s").Should(Succeed())
	})

	When("IP has no IP", func() {
		BeforeEach(func() {
			ip.Spec.IP = nil
		})

		It("should do nothing", func(ctx SpecContext) {
			var oobs oobv1alpha1.OOBList
			Expect(k8sClient.List(ctx, &oobs, client.InNamespace(ns))).To(Succeed())
			Expect(len(oobs.Items)).To(Equal(0))
		})
	})

	Describe("reconcile()", func() {
		BeforeEach(func() {
			ipReconciler.disable()
		})

		JustBeforeEach(func(ctx SpecContext) {
			res, err = ipReconciler.reconcile(ctx, controllerruntime.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: "ip"}})
		})

		When("IP does not exist", func() {
			BeforeEach(func() {
				ip.Labels = nil
			})

			JustBeforeEach(func(ctx SpecContext) {
				Expect(k8sClient.Delete(ctx, ip)).To(Succeed())
				Eventually(func(g Gomega, ctx SpecContext) {
					g.Expect(apierrors.IsNotFound(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "ip"}, ip))).To(BeTrue())
				}, ctx, "3s").Should(Succeed())

				res, err = ipReconciler.reconcile(ctx, controllerruntime.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: "ip"}})
			})

			It("should do nothing", func(ctx SpecContext) {
				Expect(err).NotTo(HaveOccurred())
				Expect(res).To(Equal(reconcile.Result{}))

				var oobs oobv1alpha1.OOBList
				Expect(k8sClient.List(ctx, &oobs, client.InNamespace(ns))).To(Succeed())
				Expect(len(oobs.Items)).To(Equal(0))
			})
		})

		When("IP has no MAC", func() {
			BeforeEach(func() {
				ip.Labels = nil
			})

			It("should do nothing", func(ctx SpecContext) {
				Expect(err).NotTo(HaveOccurred())
				Expect(res).To(Equal(reconcile.Result{}))

				var oobs oobv1alpha1.OOBList
				Expect(k8sClient.List(ctx, &oobs, client.InNamespace(ns))).To(Succeed())
				Expect(len(oobs.Items)).To(Equal(0))
			})
		})

		When("IP has an invalid MAC", func() {
			BeforeEach(func() {
				ip.Labels = map[string]string{
					"mac": "invalid",
				}
			})

			It("should return error", func(ctx SpecContext) {
				Expect(err).To(MatchError("invalid MAC address: invalid"))
			})
		})

		When("IP has the correct IP", func() {
			var uid types.UID
			var generation int64

			BeforeEach(func(ctx SpecContext) {
				oob := oobv1alpha1.OOB{
					TypeMeta: metav1.TypeMeta{
						APIVersion: oobv1alpha1.GroupVersion.String(),
						Kind:       "OOB",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: ns,
						Name:      "oob",
					},
				}
				Expect(k8sClient.Patch(ctx, &oob, client.Apply, client.FieldOwner("test"), client.ForceOwnership)).To(Succeed())
				Eventually(func(g Gomega, ctx SpecContext) {
					g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob"}, &oob)).To(Succeed())
				}, ctx, "3s").Should(Succeed())
				oob = oobv1alpha1.OOB{
					TypeMeta: metav1.TypeMeta{
						APIVersion: oobv1alpha1.GroupVersion.String(),
						Kind:       "OOB",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: ns,
						Name:      "oob",
					},
					Status: oobv1alpha1.OOBStatus{
						IP:  "1.2.3.4",
						Mac: "012345abcdef",
					},
				}
				Expect(k8sClient.Status().Patch(ctx, &oob, client.Apply, client.FieldOwner("test"), client.ForceOwnership)).To(Succeed())
				Eventually(func(g Gomega, ctx SpecContext) {
					g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob"}, &oob)).To(Succeed())
					g.Expect(oob.Status.IP).To(Equal("1.2.3.4"))
				}, ctx, "3s").Should(Succeed())
				uid = oob.UID
				generation = oob.Generation
			})

			It("should do nothing", func(ctx SpecContext) {
				Expect(err).NotTo(HaveOccurred())
				Expect(res).To(Equal(reconcile.Result{}))

				var oob oobv1alpha1.OOB
				Eventually(func(g Gomega, ctx SpecContext) {
					g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob"}, &oob)).To(Succeed())
				}, ctx, "7s").WithContext(ctx).Should(Succeed())
				Expect(oob.UID).To(Equal(uid))
				Expect(oob.Generation).To(Equal(generation))
			})
		})

		When("IP has a new IP and a MAC", func() {
			It("should create a correct OOB object", func(ctx SpecContext) {
				Expect(err).NotTo(HaveOccurred())
				Expect(res).To(Equal(reconcile.Result{}))

				var oob oobv1alpha1.OOB
				Eventually(func(g Gomega, ctx SpecContext) {
					g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "mac-012345abcdef"}, &oob)).To(Succeed())
				}, ctx, "7s").Should(Succeed())
				Expect(oob.Spec.Filler).NotTo(BeNil())
				Expect(*oob.Spec.Filler).To(BeNumerically(">", 0))
				Expect(oob.Status.IP).To(Equal("1.2.3.4"))
				Expect(oob.Status.Mac).To(Equal("012345abcdef"))
				Expect(len(oob.Status.Conditions)).To(Equal(1))
				Expect(oob.Status.Conditions[0].Type).To(Equal("Ready"))
				Expect(oob.Status.Conditions[0].Status).To(Equal(metav1.ConditionStatus("False")))
				Expect(oob.Status.Conditions[0].Reason).To(Equal("NewIP"))
			})
		})
	})

	Describe("ensureUniqueOOBByMac()", func() {
		var oob *oobv1alpha1.OOB

		BeforeEach(func() {
			ipReconciler.disable()
		})

		JustBeforeEach(func(ctx SpecContext) {
			oob, err = ipReconciler.ensureUniqueOOBByMac(ctx, ns, "012345abcdef")
		})

		When("no OOB exists", func() {
			It("should do nothing", func(ctx SpecContext) {
				Expect(err).NotTo(HaveOccurred())
				Expect(oob).To(BeNil())
			})
		})

		When("one or more OOBs exist", func() {
			var oob0, oob1 oobv1alpha1.OOB

			BeforeEach(func(ctx SpecContext) {
				oob0 = oobv1alpha1.OOB{
					TypeMeta: metav1.TypeMeta{
						APIVersion: oobv1alpha1.GroupVersion.String(),
						Kind:       "OOB",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: ns,
						Name:      "oob0",
					},
				}
				Expect(k8sClient.Patch(ctx, &oob0, client.Apply, client.FieldOwner("test"), client.ForceOwnership)).To(Succeed())
				Eventually(func(g Gomega, ctx SpecContext) {
					g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob0"}, &oob0)).To(Succeed())
				}, ctx, "3s").Should(Succeed())
				oob0 = oobv1alpha1.OOB{
					TypeMeta: metav1.TypeMeta{
						APIVersion: oobv1alpha1.GroupVersion.String(),
						Kind:       "OOB",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: ns,
						Name:      "oob0",
					},
					Status: oobv1alpha1.OOBStatus{
						IP:  "1.2.3.4",
						Mac: "012345abcdef",
					},
				}
				Expect(k8sClient.Status().Patch(ctx, &oob0, client.Apply, client.FieldOwner("test"), client.ForceOwnership)).To(Succeed())
				Eventually(func(g Gomega, ctx SpecContext) {
					g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob0"}, &oob0)).To(Succeed())
					g.Expect(oob0.Status.Mac).To(Equal("012345abcdef"))
				}, ctx, "3s").Should(Succeed())
			})

			When("one OOB exists", func() {
				It("should return the existing OOB", func(ctx SpecContext) {
					Expect(err).NotTo(HaveOccurred())
					Expect(oob.UID).To(Equal(oob0.UID))
					Expect(oob.Generation).To(Equal(oob0.Generation))
				})
			})

			When("multiple OOBs exist", func() {
				BeforeEach(func(ctx SpecContext) {
					oob1 = oobv1alpha1.OOB{
						TypeMeta: metav1.TypeMeta{
							APIVersion: oobv1alpha1.GroupVersion.String(),
							Kind:       "OOB",
						},
						ObjectMeta: metav1.ObjectMeta{
							Namespace: ns,
							Name:      "oob1",
						},
					}
					time.Sleep(time.Second)
					Expect(k8sClient.Patch(ctx, &oob1, client.Apply, client.FieldOwner("test"), client.ForceOwnership)).To(Succeed())
					Eventually(func(g Gomega, ctx SpecContext) {
						g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob1"}, &oob1)).To(Succeed())
					}, ctx, "3s").Should(Succeed())
					oob1 = oobv1alpha1.OOB{
						TypeMeta: metav1.TypeMeta{
							APIVersion: oobv1alpha1.GroupVersion.String(),
							Kind:       "OOB",
						},
						ObjectMeta: metav1.ObjectMeta{
							Namespace: ns,
							Name:      "oob1",
						},
						Status: oobv1alpha1.OOBStatus{
							IP:  "1.2.3.4",
							Mac: "012345abcdef",
						},
					}
					Expect(k8sClient.Status().Patch(ctx, &oob1, client.Apply, client.FieldOwner("test"), client.ForceOwnership)).To(Succeed())
					Eventually(func(g Gomega, ctx SpecContext) {
						g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob1"}, &oob1)).To(Succeed())
						g.Expect(oob1.Status.Mac).To(Equal("012345abcdef"))
					}, ctx, "3s").Should(Succeed())
				})

				It("should return the latest OOB", func(ctx SpecContext) {
					Expect(err).NotTo(HaveOccurred())
					Expect(oob.UID).To(Equal(oob1.UID))
					Expect(oob.Generation).To(Equal(oob1.Generation))
				})
			})

		})
	})
})
