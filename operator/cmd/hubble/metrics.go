// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package hubble

import (
	"github.com/spf13/cobra"
)

const RetinaOperatorMetricsNamespace = "networkobservability_operator"

// MetricsCmd represents the metrics command for the operator.
var MetricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Access metric status of the operator",
}
