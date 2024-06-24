// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package hubble

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type ProviderFlagsHooks interface {
	RegisterProviderFlag(cmd *cobra.Command, vp *viper.Viper)
}
