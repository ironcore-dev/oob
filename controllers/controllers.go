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
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func validateOwnerReference(obj client.Object, uid types.UID, apiVersion, kind, name string) error {
	match := false
	for _, ref := range obj.GetOwnerReferences() {
		if ref.UID == uid {
			if ref.APIVersion != apiVersion || ref.Kind != kind || ref.Name != name {
				return fmt.Errorf("UID matches but API version, kind, or name do not")
			}
			if ref.Controller == nil || *ref.Controller == false {
				return fmt.Errorf("controller flag not set to true in matching reference")
			}
			match = true
		} else if ref.Controller != nil && *ref.Controller == true {
			return fmt.Errorf("owned by another object with controller flag set to true: %v", ref.UID)
		}
	}
	if !match {
		return fmt.Errorf("not owned by specified object")
	}
	return nil
}
