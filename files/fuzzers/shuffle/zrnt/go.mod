module fuzz

go 1.14

require (
	github.com/protolambda/zrnt v0.10.1
	helper v0.0.0-00010101000000-000000000000 // indirect
)

replace github.com/protolambda/zrnt => github.com/protolambda/zrnt v0.10.1

replace helper => ../../../lib/go/src/helper
