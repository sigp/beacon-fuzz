// TODO how can go modules depend on goPath packages?
module github.com/sigp/beacon-fuzz/tools/corpora-extract

go 1.12

require (
	github.com/spf13/cobra v0.0.3
)

replace helper => ../../lib/go/src/helper
replace github.com/protolambda/zrnt => github.com/protolambda/zrnt v0.10.1
