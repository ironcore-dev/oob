// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package rand

import (
	"math"

	"k8s.io/apimachinery/pkg/util/rand"
)

func NewRandInt64() *int64 {
	return &(&struct{ x int64 }{1 + rand.Int63nRange(0, math.MaxInt64)}).x
}
