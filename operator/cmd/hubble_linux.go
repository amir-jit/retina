// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package cmd

import (
	"fmt"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
	"github.com/microsoft/retina/operator/cmd/hubble"
	"github.com/spf13/cobra"
)

var (
	h   = hive.New(hubble.Operator)
	cmd = &cobra.Command{
		Use:   "v2",
		Short: "Start the Retina operator V2",
		Run: func(cobraCmd *cobra.Command, _ []string) {
			if v, _ := cobraCmd.Flags().GetBool("version"); v {
				fmt.Println("Starting Retina Operator V2")
			}
			hubble.Execute(cobraCmd, h)
		},
	}
)

func init() {
	h.RegisterFlags(cmd.Flags())
	cmd.AddCommand(h.Command())

	hubble.InitGlobalFlags(cmd, h.Viper())

	// Enable fallback to direct API probing to check for support of Leases in
	// case Discovery API fails.
	h.Viper().Set(option.K8sEnableAPIDiscovery, true)

	cmd.AddCommand(
		hubble.MetricsCmd,
		h.Command(),
	)
	// not sure where flags hooks is set
	for _, hook := range hubble.FlagsHooks {
		hook.RegisterProviderFlag(cmd, h.Viper())
	}

	rootCmd.AddCommand(cmd)
}
