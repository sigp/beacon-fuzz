package app

import (
    "helper"
    "io/ioutil"
    "fmt"
    "errors"
)

var targetMap = map[string]helper.InputType{
    "attestation": helper.INPUT_TYPE_ATTESTATION,
    "attester_slashing": helper.INPUT_TYPE_ATTESTER_SLASHING,
    "block": helper.INPUT_TYPE_BLOCK,
    "block_header": helper.INPUT_TYPE_BLOCK_HEADER,
    "deposit": helper.INPUT_TYPE_DEPOSIT,
    "proposer_slashing": helper.INPUT_TYPE_PROPOSER_SLASHING,
    "voluntary_exit": helper.INPUT_TYPE_VOLUNTARY_EXIT,
}

func Extract(target string, inputFile string, outputFile string, verbose bool) error {
    targetType, ok := targetMap[target]
    if !ok {
        return fmt.Errorf("Invalid target name: %v\n", target)
    }
    helper.SetInputType(targetType)
    if verbose {
        fmt.Printf("Reading input file: %v\n", inputFile)
    }
    data, err := ioutil.ReadFile(inputFile)
    if err != nil {
        return err
    }
    if len(data) == 0 {
        return fmt.Errorf("File: %q is empty\n", inputFile)
    }
    if verbose {
        fmt.Printf("Performing preprocessing.\n")
    }
    size := helper.SSZPreprocess(data)
    if size == 0 {
        return errors.New("Preprocessing failed.\n")
    }
    if verbose {
        fmt.Printf("Preprocess return size: %v\n", size)
    }
    var result = make([]byte, size, size)
    if verbose {
        fmt.Printf("Extracting preprocessed data.\n")
    }
    helper.SSZPreprocessGetReturnData(result)
    if verbose {
        fmt.Printf("Writing results to: %v\n", outputFile)
    }
    err = ioutil.WriteFile(outputFile, result, 0644)
    return err
}
