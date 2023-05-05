package controllers

import (
	"time"

	oobv1alpha1 "github.com/onmetal/oob-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("OOB controller", func() {
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

		ipReconciler.disable()
		oobReconciler.enable()
	})

	Context("->", func() {
		var oob *oobv1alpha1.OOB
		BeforeEach(func() {
			oob = &oobv1alpha1.OOB{
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
		})

		JustBeforeEach(func(ctx SpecContext) {
			status := oob.Status
			Expect(k8sClient.Patch(ctx, oob, client.Apply, client.FieldOwner("test"), client.ForceOwnership)).To(Succeed())
			Eventually(func(g Gomega, ctx SpecContext) {
				var obj oobv1alpha1.OOB
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob"}, &obj)).To(Succeed())
			}, ctx, "3s").Should(Succeed())
			oob = &oobv1alpha1.OOB{
				TypeMeta: metav1.TypeMeta{
					APIVersion: oobv1alpha1.GroupVersion.String(),
					Kind:       "OOB",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: ns,
					Name:      "oob",
				},
				Status: status,
			}
			Expect(k8sClient.Status().Patch(ctx, oob, client.Apply, client.FieldOwner("test"), forceOwnershipUglyWorkaround)).To(Succeed())
			Eventually(func(g Gomega, ctx SpecContext) {
				var obj oobv1alpha1.OOB
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob"}, &obj)).To(Succeed())
				g.Expect(obj.Status.Mac).To(Equal(oob.Status.Mac))
			}, ctx, "3s").Should(Succeed())
		})

		When("OOB is being ignored", func() {
			BeforeEach(func() {
				oob.Annotations = map[string]string{"oob-operator.onmetal.de/ignore": "true"}
			})

			It("should do nothing", func(ctx SpecContext) {
				var oobs oobv1alpha1.OOBList
				Expect(k8sClient.List(ctx, &oobs, client.InNamespace(ns))).To(Succeed())
				Expect(len(oobs.Items)).To(Equal(1))
				Expect(oobs.Items[0].UID == oob.UID)
				Expect(oobs.Items[0].Generation == oob.Generation)
			})
		})

		When("OOB is being disregarded", func() {
			BeforeEach(func() {
				oob.Annotations = map[string]string{"oob-operator.onmetal.de/ignore": "true"}
			})

			It("should do nothing", func(ctx SpecContext) {
				var oobs oobv1alpha1.OOBList
				Expect(k8sClient.List(ctx, &oobs, client.InNamespace(ns))).To(Succeed())
				Expect(len(oobs.Items)).To(Equal(1))
				Expect(oobs.Items[0].UID == oob.UID)
				Expect(oobs.Items[0].Generation == oob.Generation)
			})
		})
	})

	Context("|", func() {
		BeforeEach(func() {
			oobReconciler.disable()
		})

		Describe("reconcile()", func() {
			// TODO
		})

		Describe("applyErrorCondition()", func() {
			// TODO
		})

		Describe("applyCondition()", func() {
			// TODO
		})

		Describe("clearNoneFields()", func() {
			// TODO
		})

		Describe("ensureGoodCredentials()", func() {
			// TODO
		})

		Describe("getCredentials()", func() {
			// TODO
		})

		Describe("tagMapFromK8s()", func() {
			// TODO
		})

		Describe("tagsToK8s()", func() {
			// TODO
		})

		Describe("createCredentials()", func() {
			// TODO
		})

		Describe("persistCredentials()", func() {
			// TODO
		})

		Describe("ensureCorrectUUIDAndName()", func() {
			// TODO
		})

		Describe("ensureUniqueOOBByUUID()", func() {
			var oob *oobv1alpha1.OOB
			var err error
			JustBeforeEach(func(ctx SpecContext) {
				oob, err = oobReconciler.ensureUniqueOOBByUUID(ctx, ns, "00000000-0000-0000-0000-123456789abc")
			})

			When("no OOB exists", func() {
				It("should do nothing", func(ctx SpecContext) {
					Expect(err).NotTo(HaveOccurred())
					Expect(oob).To(BeNil())
				})
			})

			When("one or more OOBs exist", func() {
				var oob0 oobv1alpha1.OOB
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
							UUID: "00000000-0000-0000-0000-123456789abc",
						},
					}
					Expect(k8sClient.Status().Patch(ctx, &oob0, client.Apply, client.FieldOwner("test"), forceOwnershipUglyWorkaround)).To(Succeed())
					Eventually(func(g Gomega, ctx SpecContext) {
						g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob0"}, &oob0)).To(Succeed())
						g.Expect(oob0.Status.UUID).To(Equal("00000000-0000-0000-0000-123456789abc"))
					}, ctx, "3s").Should(Succeed())
				})

				When("one OOB exists", func() {
					It("should return the existing OOB", func(ctx SpecContext) {
						Expect(err).NotTo(HaveOccurred())
						Expect(oob).NotTo(BeNil())
						Expect(oob.UID).To(Equal(oob0.UID))
						Expect(oob.Generation).To(Equal(oob0.Generation))
					})
				})

				When("multiple OOBs exist", func() {
					var oob1 oobv1alpha1.OOB
					BeforeEach(func(ctx SpecContext) {
						time.Sleep(time.Second)
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
								UUID: "00000000-0000-0000-0000-123456789abc",
							},
						}
						Expect(k8sClient.Status().Patch(ctx, &oob1, client.Apply, client.FieldOwner("test"), forceOwnershipUglyWorkaround)).To(Succeed())
						Eventually(func(g Gomega, ctx SpecContext) {
							g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "oob1"}, &oob1)).To(Succeed())
							g.Expect(oob0.Status.UUID).To(Equal("00000000-0000-0000-0000-123456789abc"))
						}, ctx, "3s").Should(Succeed())
					})

					It("should return the latest OOB", func(ctx SpecContext) {
						Expect(err).NotTo(HaveOccurred())
						Expect(oob).NotTo(BeNil())
						Expect(oob.UID).To(Equal(oob1.UID))
						Expect(oob.Generation).To(Equal(oob1.Generation))
					})
				})
			})
		})

		Describe("replaceOOB()", func() {
			// TODO
		})

		Describe("setNTPServers()", func() {
			// TODO
		})

		Describe("setStatusFields()", func() {
			// TODO
		})

		Describe("applyLocatorLED()", func() {
			// TODO
		})

		Describe("applyPower()", func() {
			// TODO
		})

		Describe("applyReset()", func() {
			// TODO
		})
	})
})
