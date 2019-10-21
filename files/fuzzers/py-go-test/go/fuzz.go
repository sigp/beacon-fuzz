package fuzz

func Fuzz(data []byte) []byte {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	/* From https://github.com/golang/go/wiki/SliceTricks#reversing */
	for i := len(dataCopy)/2 - 1; i >= 0; i-- {
		opp := len(dataCopy) - 1 - i
		dataCopy[i], dataCopy[opp] = dataCopy[opp], dataCopy[i]
	}

	return dataCopy
}
