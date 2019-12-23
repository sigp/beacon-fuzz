package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
    "github.com/sigp/beacon-fuzz/tools/corpora-extract/app"
)

var verbose bool = false
var corpusPath string
var outputFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
    // TODO(gnattishness) optional output file as a positional arg
	Use:   "corpora-extract TARGET_NAME INPUT_FILE",
	Short: "Converts beacon-fuzz corpora to input as provided to implementation harnesses",
    Long: `Converts beacon-fuzz corpora to input as provided to implementation harnesses:

Requires ETH2_FUZZER_STATE_CORPUS_PATH to be set.
TODO flesh out`,
    Args: cobra.ExactArgs(2),
    RunE: func(cmd *cobra.Command, args []string) error {
        if len(corpusPath) > 0 {
            err := os.Setenv("ETH2_FUZZER_STATE_CORPUS_PATH", corpusPath)
            if err != nil {
                return fmt.Errorf("unable to set ETH2_FUZZER_STATE_CORPUS_PATH to %q", corpusPath)
            }
        }
        err := app.Extract(args[0], args[1], outputFile, verbose)
        return err
    },
}


// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize()
    rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
    rootCmd.Flags().StringVar(&corpusPath, "state-dir", "", "directory containing ssz-encoded BeaconState corpora. ETH2_FUZZER_STATE_CORPUS_PATH by default.")
    rootCmd.Flags().StringVarP(&outputFile, "out-file", "o", "out.ssz", "ssz-encoded file containing data suitable for passing to an implementation harness. './out.ssz' by default.")

    // TODO allow output as yaml

}
