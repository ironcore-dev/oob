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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// OOBSpec defines the desired state of OOB
type OOBSpec struct {
	//+optional
	//+kubebuilder:validation:Pattern=`^(?:None|On|Off|Blinking)$`
	LocatorLED string `json:"locatorLED,omitempty"`

	//+optional
	//+kubebuilder:validation:Pattern=`^(?:None|On|Off|OffImmediate)$`
	Power string `json:"power,omitempty"`

	//+optional
	//+kubebuilder:validation:Pattern=`^(?:None|Reset|ResetImmediate)$`
	Reset string `json:"reset,omitempty"`

	//+optional
	//+kubebuilder:validation:Minimum=0
	Filler *int64 `json:"filler,omitempty"`
}

type TagSpec struct {
	//+kubebuilder:validation:MinLength=1
	Key string `json:"key,omitempty"`

	//+kubebuilder:validation:MinLength=1
	Value string `json:"value,omitempty"`
}

// OOBStatus defines the observed state of OOB
type OOBStatus struct {
	//+optional
	//+kubebuilder:validation:Pattern=`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
	UUID string `json:"uuid,omitempty"`

	//+optional
	//+kubebuilder:validation:Pattern=`^[0-9a-f]{12}$`
	Mac string `json:"mac,omitempty"`

	//+optional
	//+kubebuilder:validation:Pattern=`((^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$)|(^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$))`
	IP string `json:"ip,omitempty"`

	//+optional
	//+kubebuilder:validation:MinLength=1
	Protocol string `json:"protocol,omitempty"`

	//+optional
	Tags []TagSpec `json:"tags,omitempty"`

	//+optional
	//+kubebuilder:validation:Minimum=0
	//+kubebuilder:validation:Maximum=65536
	Port int `json:"port,omitempty"`

	//+optional
	//+kubebuilder:validation:MinLength=1
	Type string `json:"type,omitempty"`

	//+optional
	Capabilities []string `json:"capabilities,omitempty"`

	//+optional
	//+kubebuilder:validation:MinLength=1
	Manufacturer string `json:"manufacturer,omitempty"`

	//+optional
	//+kubebuilder:validation:MinLength=1
	SerialNumber string `json:"serialNumber,omitempty"`

	//+optional
	//+kubebuilder:validation:MinLength=1
	SKU string `json:"sku,omitempty"`

	//+optional
	//+kubebuilder:validation:Pattern=`^(?:On|Off|Blinking)$`
	LocatorLED string `json:"locatorLED,omitempty"`

	//+optional
	//+kubebuilder:validation:Pattern=`^(?:On|Off)$`
	Power string `json:"power,omitempty"`

	//+optional
	ShutdownDeadline *metav1.Time `json:"shutdownDeadline,omitempty"`

	//+optional
	//+kubebuilder:validation:Pattern=`^(?:Ok|Waiting|TimedOut)$`
	OS string `json:"os,omitempty"`

	//+optional
	//+kubebuilder:validation:MinLength=1
	OSReason string `json:"osReason,omitempty"`

	//+optional
	OSReadDeadline *metav1.Time `json:"osReadDeadline,omitempty"`

	//+optional
	Console string `json:"console,omitempty"`

	//+optional
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`

	//+optional
	//+kubebuilder:validation:MinLength=1
	FWVersion string `json:"fwVersion,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="UUID",type=string,JSONPath=`.status.uuid`,description="UUID"
//+kubebuilder:printcolumn:name="IP",type=string,JSONPath=`.status.ip`,description="IP",priority=1
//+kubebuilder:printcolumn:name="MAC",type=string,JSONPath=`.status.mac`,description="MAC",priority=1
//+kubebuilder:printcolumn:name="POWER",type=string,JSONPath=`.status.power`,description="Power State"
//+kubebuilder:printcolumn:name="LED",type=string,JSONPath=`.status.locatorLED`,description="Locator LED"
//+kubebuilder:printcolumn:name="READY",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`,description="Readyness"
//+kubebuilder:printcolumn:name="MANUFACTURER",type=string,JSONPath=`.status.manufacturer`,description="Manufacturer",priority=1
//+kubebuilder:printcolumn:name="TYPE",type=string,JSONPath=`.status.type`,description="Type",priority=1
//+kubebuilder:printcolumn:name="DESCRIPTION",type=string,JSONPath=`.metadata.annotations['description']`,description="Description",priority=1

// OOB is the Schema for the oobs API
type OOB struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OOBSpec   `json:"spec,omitempty"`
	Status OOBStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// OOBList contains a list of OOB
type OOBList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OOB `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OOB{}, &OOBList{})
}
