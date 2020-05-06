// Modifications copyright (C) 2020 Sigma Prime Pty Ltd. All rights reserved.

// TODO check for go114-fuzz-build too
// Originally based on dvyukov/go-fuzz-build and its interface.
// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"go/token"
	"go/types"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"golang.org/x/tools/go/packages"
)

var (
	flagTags       = flag.String("tags", "", "a comma-separated list of build tags to consider satisfied during the build.")
	flagOut        = flag.String("o", "", "output file. (default [pkg1Name]-fuzz.a)")
	flagWork       = flag.Bool("work", false, "do not delete generated main file.\nprint the name of the temporary work directory and do not delete it when exiting.")
	flagRace       = flag.Bool("race", false, "enable race detection.")
	flagX          = flag.Bool("x", false, "print the commands.")
	flagV          = flag.Bool("v", false, "verbose build.")
	flagPreserve   = flag.String("preserve", "", "a comma-separated list of import paths not to instrument.")
	flagRuntimeCov = flag.Bool("cover-runtime", false, "Provide coverage instrumentation for runtime (normally ignored).")
	flagMainCov    = flag.Bool("cover-main", false, "Provide coverage instrumentation for generated main package (normally ignored).")
)

// TODO option to build without any coverage?

type Exit struct{ Code int }

type HarnessSpec struct {
	Path         string
	FuncName     string
	ExportPrefix string
}

// TODO(gnattishness) can also build in an initialization func if needed

// exit code handler thanks https://stackoverflow.com/a/27630092
func handleExit() {
	if e := recover(); e != nil {
		if exit, ok := e.(Exit); ok == true {
			os.Exit(exit.Code)
		}
		panic(e) // not an Exit, bubble up
	}
}

func main() {
	defer handleExit()

	flag.Usage = func() {
		usageStr := "Usage: %s [options] export_prefix[,pkg_or_module_path][,func_name] [export_prefix[,pkg_or_module_path][,func_name] ...] \n\n" +
			"Build a `c-archive` static library exporting Fuzz harnesses suitable for Beacon Fuzz.\n\n" +
			"Harnesses expose C functions with the following naming convention: \"export_prefixBFUZZGolangTestOneInput\"\n" +
			"pkg_or_module_path:    package containing Go fuzz harness (default \".\")\n" +
			"func_name:             name of Go fuzz harness function (default \"Fuzz\")\n\n" +
			"Use module name to load go.mod dependencies correctly.\n\n" +
			"Options:\n"

		fmt.Fprintf(os.Stderr, usageStr, os.Args[0])

		flag.PrintDefaults()

		extendedUsage := "\n\n" +
			"Extended details:\n" +
			"(only required for beacon-fuzz implementors):\n\n" +
			"Each harness exports the following C function:\n" +
			"   `struct export_prefixBFUZZGolangTestOneInput_return export_prefixBFUZZGolangTestOneInput(unsigned char* data, size_t size)`\n" +
			"Where\n" +
			"   `struct export_prefixBFUZZGolangTestOneInput_return`\n" +
			"       contains the equivalent of a `(size_t resultSize, int errnum)` tuple.\n" +
			"   `resultSize`\n" +
			"       is the size of the Fuzz harness output after successful operation.\n" +
			"   `errnum!=0`\n" +
			"       indicates the Fuzz harness returned an error, and no result should be viewed.\n\n" +
			"After a successful result, the harness result can be retrieved by passing a buffer of at least `resultSize` to `BFUZZGolangGetReturnData(uint8_t* buf)`\n" +
			"NOTE: this should only be retrieved once when no error is present, or memory corruption may occur.\n\n" +
			"See the generated `.h` file for more details, or the `main.*.go` left when using `-work`.\n"
		fmt.Fprintf(os.Stderr, extendedUsage)
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		panic(Exit{1})
	}

	harnesses := parseArgs(flag.Args())
	if len(harnesses) == 0 {
		// the previous NArg check should avoid this
		panic("Something went wrong parsing args.")
	}

	buildFlags := []string{
		"-buildmode", "c-archive",
		"-gcflags", "all=-d=libfuzzer",
		"-tags", getTags(flagTags),
		"-trimpath",
	}

	toIgnore := calcIgnore(flagPreserve, !*flagRuntimeCov, !*flagMainCov) // calculate set of packages to ignore

	for _, p := range toIgnore {
		buildFlags = append(buildFlags, "-gcflags", p+"=-d=libfuzzer=0")
	}

	if *flagRace {
		buildFlags = append(buildFlags, "-race")
	}
	if *flagV {
		buildFlags = append(buildFlags, "-v")
	}
	if *flagWork {
		buildFlags = append(buildFlags, "-work")
	}
	if *flagX {
		buildFlags = append(buildFlags, "-x")
	}

	pkgs := make([]packages.Package, len(harnesses))
	// validate package paths
	for i, h := range harnesses {
		pkgs[i] = *loadPkg(h.Path, buildFlags)
	}

	// TODO will this be a problem if its being called from within a package,
	// so will then have "main" and the pkg in the same dir?
	mainFile, err := ioutil.TempFile(".", "main.*.go")
	if err != nil {
		safeLogFatal("failed to create temporary file:", err)
	}
	if !*flagWork {
		defer os.Remove(mainFile.Name())
	}

	err = mainSrc.Execute(mainFile, harnesses)
	if err != nil {
		safeLogFatalf("failed to execute template: %v", err)
	}
	if err := mainFile.Close(); err != nil {
		safeLogFatalf("couldn't close file: %v", err)
	}

	out := *flagOut
	if out == "" {
		out = pkgs[0].Name + "-fuzz.a"
	}

	args := []string{"build", "-o", out}
	args = append(args, buildFlags...)
	args = append(args, mainFile.Name())
	cmd := exec.Command("go", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		safeLogFatalf("failed to build packages: %v", err)
	}
}

func parseArgs(args []string) []HarnessSpec {
	harnesses := make([]HarnessSpec, len(args))
	for i, arg := range args {
		// TODO does this get dereferenced or do we have to do it ourselves?
		harnesses[i] = *parseArg(arg)
	}
	return harnesses
}

func parseArg(arg string) *HarnessSpec {
	// TODO(gnattishness) should I ensure none of the spec sections are "" ?
	parts := strings.Split(arg, ",")
	partsLen := len(parts)
	if partsLen > 3 {
		safeLogFatalf("unexpected number of comma-separated sections in arg: `%v`. Got %v, max 3", arg, partsLen)
	}
	if partsLen == 0 || parts[0] == "" {
		safeLogFatalf("invalid arg: `%v`. Need to at least provide `export_prefix`", arg)
	}
	path := "."
	if partsLen >= 2 && parts[1] != "" {
		path = parts[1]
	}
	if strings.Contains(path, "...") {
		safeLogFatal("package path must not contain ... wildcards")
	}
	name := "Fuzz"
	if partsLen == 3 && parts[2] != "" {
		name = parts[2]
		if !isFuzzFuncName(name) {
			safeLogFatalf("provided FuncName=%v, but %v is not a valid function name", name, name)
		}
	}
	return &HarnessSpec{
		Path:         path,
		FuncName:     name,
		ExportPrefix: parts[0],
	}
}

// loadPkg loads, parses, and typechecks pkg (the package containing the Fuzz function),
func loadPkg(path string, buildFlags []string) *packages.Package {

	// TODO type checking too?
	pkgs, err := packages.Load(&packages.Config{
		Mode:       packages.NeedName,
		BuildFlags: buildFlags,
	}, "pattern="+path)
	if err != nil {
		safeLogFatalf("failed to load packages: %v", err)
	}
	if packages.PrintErrors(pkgs) != 0 {
		panic(Exit{1})
	}
	if len(pkgs) != 1 {
		// TODO might need to join strings
		safeLogFatalf("package path: %v matched multiple packages: %v", path, pkgs)
	}
	pkg := pkgs[0]

	if pkg.Name == "main" {
		safeLogFatal("cannot fuzz package main")
	}

	return pkg

	/*
		// Resolve pkg.
		// See https://golang.org/issue/30826 and https://golang.org/issue/30828.
		rescfg := basePackagesConfig()
		rescfg.Mode = packages.NeedName
		rescfg.BuildFlags = []string{"-tags", getTags()}
		respkgs, err := packages.Load(rescfg, pkg)
		if err != nil {
			safeLogFatalf("could not resolve package %q: %v", pkg, err)
		}
		if len(respkgs) != 1 {
			paths := make([]string, len(respkgs))
			for i, p := range respkgs {
				paths[i] = p.PkgPath
			}
			safeLogFatalf("cannot build multiple packages, but %q resolved to: %v", pkg, strings.Join(paths, ", "))
		}
		if respkgs[0].Name == "main" {
			safeLogFatal("cannot fuzz package main")
		}
		pkgpath := respkgs[0].PkgPath

		// Load, parse, and type-check all packages.
		// We'll use the type information later.
		// This also provides better error messages in the case
		// of invalid code than trying to compile instrumented code.
		cfg := basePackagesConfig()
		cfg.Mode = packages.LoadAllSyntax
		cfg.BuildFlags = []string{"-tags", getTags()}
		// use custom ParseFile in order to get comments
		cfg.ParseFile = func(fset *token.FileSet, filename string, src []byte) (*ast.File, error) {
			return parser.ParseFile(fset, filename, src, parser.ParseComments)
		}
		// We need to load:
		// * the target package, obviously
		// * go-fuzz-dep, since we use it for instrumentation
		// * reflect, if we are using libfuzzer, since its generated main function requires it
		loadpkgs := []string{pkg, "github.com/dvyukov/go-fuzz/go-fuzz-dep"}
		if *flagLibFuzzer {
			loadpkgs = append(loadpkgs, "reflect")
		}
		initial, err := packages.Load(cfg, loadpkgs...)
		if err != nil {
			safeLogFatalf("could not load packages: %v", err)
		}

		// Stop if any package had errors.
		if packages.PrintErrors(initial) > 0 {
			safeLogFatalf("typechecking of %v failed", pkg)
		}

		c.pkgs = initial

		// Find the fuzz package among c.pkgs.
		for _, p := range initial {
			if p.PkgPath == pkgpath {
				c.fuzzpkg = p
				break
			}
		}
		if c.fuzzpkg == nil {
			safeLogFatal("internal error: failed to find fuzz package; please file an issue")
		}

		// Find all fuzz functions in fuzzpkg.
		foundFlagFunc := false
		s := c.fuzzpkg.Types.Scope()
		for _, n := range s.Names() {
			if !isFuzzFuncName(n) {
				continue
			}
			// Check that n is a function with an appropriate signature.
			typ := s.Lookup(n).Type()
			sig, ok := typ.(*types.Signature)
			if !ok || sig.Variadic() || !isFuzzSig(sig) {
				if n == *flagFunc {
					safeLogFatalf("provided -func=%v, but %v is not a fuzz function", *flagFunc, *flagFunc)
				}
				continue
			}
			// n is a fuzz function.
			c.allFuncs = append(c.allFuncs, n)
			foundFlagFunc = foundFlagFunc || n == *flagFunc
		}

		if len(c.allFuncs) == 0 {
			safeLogFatalf("could not find any fuzz functions in %v", c.fuzzpkg.PkgPath)
		}
		if len(c.allFuncs) > 255 {
			safeLogFatalf("go-fuzz-build supports a maximum of 255 fuzz functions, found %v; please file an issue", len(c.allFuncs))
		}

		if *flagFunc != "" {
			// Specific fuzz function requested.
			// If the requested function doesn't exist, fail.
			if !foundFlagFunc {
				safeLogFatalf("could not find fuzz function %v in %v", *flagFunc, c.fuzzpkg.PkgPath)
			}
		} else {
			// No specific fuzz function requested.
			// If there's only one fuzz function, mark it as preferred.
			// If there's more than one...
			//   ...for go-fuzz, that's fine; one can be specified later on the command line.
			//   ...for libfuzzer, that's not fine, as there is no way to specify one later.
			if len(c.allFuncs) == 1 {
				*flagFunc = c.allFuncs[0]
			} else if *flagLibFuzzer {
				safeLogFatalf("must specify a fuzz function with -libfuzzer, found: %v", strings.Join(c.allFuncs, ", "))
			}
		}
	*/
}

// isFuzzSig reports whether sig is of the form
//   func FuzzFunc(data []byte) ([]byte, error)
func isFuzzSig(sig *types.Signature) bool {
	// TODO(gnattishness)
	return tupleHasTypes(sig.Params(), "[]byte") && tupleHasTypes(sig.Results(), "[]byte", "error")
}

// tupleHasTypes reports whether tuple is composed of
// elements with exactly the types in types.
func tupleHasTypes(tuple *types.Tuple, types ...string) bool {
	if tuple.Len() != len(types) {
		return false
	}
	for i, t := range types {
		if tuple.At(i).Type().String() != t {
			return false
		}
	}
	return true
}

func isFuzzFuncName(name string) bool {
	if !token.IsIdentifier(name) || !token.IsExported(name) || !strings.HasPrefix(name, "Fuzz") {
		return false
	}
	return true
}

func calcIgnore(userIgnores *string, ignoreRuntime bool, ignoreMain bool) []string {

	// Use a map to avoid duplicates
	ignoreMap := map[string]bool{"syscall": true}

	// No reason to instrument these.
	if ignoreRuntime {
		ignoreMap["runtime/cgo"] = true
		ignoreMap["runtime/pprof"] = true
		ignoreMap["runtime/race"] = true

		// Roots: must not instrument these, nor any of their dependencies, to avoid import cycles.
		// Fortunately, these are mostly packages that are non-deterministic,
		// noisy (because they are low level), and/or not interesting.
		// We could manually maintain this list, but that makes go-fuzz-build
		// fragile in the face of internal standard library package changes.
		/*
		   // TODO look if this is worth keeping, relies on c.pkgs
		   roots := packagesNamed("runtime")
		   packages.Visit(roots, func(p *packages.Package) bool {
		       ignoreMap[p.PkgPath] = true
		       return true
		   }, nil)
		*/
	}

	if ignoreMain {
		ignoreMap["main"] = true
	}

	// Ignore any packages requested explicitly by the user.
	if *userIgnores != "" {
		paths := strings.Split(*userIgnores, ",")
		for _, path := range paths {
			ignoreMap[path] = true
		}
	}

	toIgnore := make([]string, len(ignoreMap))
	i := 0
	for k := range ignoreMap {
		toIgnore[i] = k
		i++
	}
	return toIgnore
}

/*
// packagesNamed extracts the packages listed in paths.
func (c *Context) packagesNamed(paths ...string) (pkgs []*packages.Package) {
	pre := func(p *packages.Package) bool {
		for _, path := range paths {
			if p.PkgPath == path {
				pkgs = append(pkgs, p)
				break
			}
		}
		return len(pkgs) < len(paths) // continue only if we have not succeeded yet
	}
	packages.Visit(c.pkgs, pre, nil)
	return pkgs
}
*/

// Because log.Fatal calls os.Exit(1) and doesn't respect defers
func safeLogFatal(v ...interface{}) {
	log.Print(v...)
	panic(Exit{1})
}

func safeLogFatalf(format string, v ...interface{}) {
	log.Printf(format, v...)
	panic(Exit{1})
}

func getTags(userTags *string) string {
	tags := "gofuzz,gofuzz_libfuzzer,libfuzzer"

	if len(*userTags) > 0 {
		tags += "," + *userTags
	}
	return tags
}

var mainSrc = template.Must(template.New("main").Parse(`
// Code generated by go-bfuzz-build. DO NOT EDIT
// NOTE: should not be used concurrently, only 1 result is stored at a time

// +build ignore

package main

import (
	"unsafe"
	"fmt"

	{{range $i, $h := .}}
	target{{- $i}} {{printf "%q" $h.Path}}
	{{end}}

)

// #include <stdint.h>
import "C"

{{/* // TODO allow initialization if needed - only needs doing if initialization
// requires some parameters from BFUZZ, otherwise init() is enough

//export BFUZZFuzzerInitialize
func BFUZZFuzzerInitialize(argc uintptr, argv uintptr) int {
	return 0
}
*/}}
var bfuzz_return_data []byte

{{range $i, $h := .}}
//export {{ $h.ExportPrefix -}} BFUZZGolangTestOneInput
func {{ $h.ExportPrefix -}} BFUZZGolangTestOneInput(data *C.uchar, size C.size_t) (resultSize C.size_t, errnum C.int) {
	// returns size of result
	// errnum is set to 1 if an error occured

	input := (*[1<<31]byte)(unsafe.Pointer(data))[:size:size]

	var result []byte

	result, err := target{{$i}}.{{$h.FuncName}}(input)

	if err != nil || result == nil {
		return 0, 1
	}

	bfuzz_return_data = result
	return C.size_t(len(bfuzz_return_data)), 0
}

{{end}}
//export BFUZZGolangGetReturnData
func BFUZZGolangGetReturnData(buf *C.uchar) {
	// copies previous result into buf
	// ensure buf is large enough to contain the result
	// NOTE: this can only be called once for each call to a successful BFUZZGolangTestOneInput,
	// as it allows the result data to be gc'd

	// NOTE: we could use C.CBytes, but that calls malloc
	// This allows us to pass a buffer from the stack

	// TODO worth checking that bfuzz_return_data != nil?

	size := len(bfuzz_return_data)

	output := (*[1<<30]byte)(unsafe.Pointer(buf))[:size:size]

	nCopied := copy(output, bfuzz_return_data)

	if (nCopied != size) {
		panic(fmt.Sprintf("Go: Unable to copy entire result. Expected %v, but only copied %v", size, nCopied))
	}

	// TODO should we keep this setting stored data to nil so it can be gc'd?
	// potentially trap for the unwary
	bfuzz_return_data = nil
}

// TODO also export a way to check the size of the stored return value?
// generally shouldn't be needed though

func main() {
}
`))
