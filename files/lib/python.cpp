#include "python.h"

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>

#include "python_coverage.h"
#include "util.h"

#if PY_MAJOR_VERSION < 3 || (PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION < 7)
#warning "Only supported for Python >= 3.7"
#endif

// Convert preprocessor parameters to strings
#define STR_(X) #X
#define STR(X) STR_(X)

// TODO(gnattishness) use pybind11?

namespace {

const std::filesystem::path venvLibSuffix = "lib/python" STR(
    PY_MAJOR_VERSION) "." STR(PY_MINOR_VERSION) "/site-packages";

// TODO(gnattishness) Interpreter wrapper class and global weak ref
// currently leaks interpreters

}  // namespace

namespace fuzzing {

class Python::Impl {
  std::string code;
  // TODO(gnattishness) have as smart pointer?
  PyObject* pFunc = nullptr;
  // TODO(gnattishness) have as smart pointer? should be unique
  // TODO(gnattishness) can we set as const? should only be set once?
  PyThreadState* thisInterpreter = nullptr;
  // TODO(gnattishness) use smart ptr? should be shared/static - only cleaned up
  // when no others exist could be a weak global pointer, with each instance
  // initializing a shared?
  // PyThreadState* mainInterpreter = nullptr;
  // TODO(gnattishness) what argv0 used for?
  // TODO(gnattishness) add config path here?
 public:
  Impl(const std::string& argv0, const std::filesystem::path& scriptPath,
       const std::optional<const std::filesystem::path>& libPath,
       const std::optional<const std::filesystem::path>& venvPath,
       const bool bls_disabled, const bool eval_paths_rel_to_file) {
    std::filesystem::path oldCwd;
    if (eval_paths_rel_to_file) {
      oldCwd = std::filesystem::current_path();
      // set current directory to that of the executable
      std::filesystem::path execDir = util::getExePath().parent_path();
      std::filesystem::current_path(execDir);
    }
    {
      // Not the fastest way to read a file, but robust
      // Based on: https://stackoverflow.com/a/43027468
      std::ifstream ifs(scriptPath, std::ifstream::in);
      if (!ifs) {
        // to stderr?
        printf("Fatal error: Cannot open script or is empty: %s\n",
               scriptPath.c_str());
        abort();
      }

      std::ostringstream ss;
      ifs >> ss.rdbuf();
      if (ifs.fail() && !ifs.eof()) {
        printf("Fatal error: Cannot read script: %s\n", scriptPath.c_str());
        abort();
      }
      code = ss.str();
    }

    // Have the first instance initialize itself as the main interpreter
    // We prefer this over having an independent main interpreter, with each
    // instance using a subinterpreter. This reduces the overall number of
    // interpreters and, in this case, each instance has a similar lifespan.
    // (I.e. it is unlikely that the "main" instance is destroyed long before
    // the other instances.)
    if (!Py_IsInitialized()) {
      // the first Python fuzzer uses the main interpreter

      Py_Initialize();
      thisInterpreter = PyThreadState_Get();

    } else {
      // Main interpreter has already been initialized
      // TODO(gnattishness) maybe need to save and restore existing ThreadState?
      PyThreadState* saved = PyThreadState_Swap(nullptr);

      thisInterpreter = Py_NewInterpreter();
      if (!thisInterpreter) {
        printf("Fatal: Py_NewInterpreter() initialization failed.");
        abort();
      }

      // ...
      // restore
      // TODO(gnattishness) restore at end?
      // PyThreadState_Swap(saved);
    }

    {
      std::ostringstream setArgv0;
      setArgv0 << "import sys\nsys.argv[0] = '" << scriptPath << "'\n";
      if (PyRun_SimpleString(setArgv0.str().c_str()) != 0) {
        printf("Fatal: Cannot set argv[0]\n");
        PyErr_Print();
        abort();
      }
    }

    {
      // NOTE: canonical throws if the file doesn't exist
      std::filesystem::path scriptRootPath =
          std::filesystem::canonical(scriptPath).parent_path();
      std::ostringstream setPath;
      // NOTE: paths appear to be converted to strings containing quotes ("), so
      // additional quotes aren't required
      setPath << "import sys\nsys.path.append(" << scriptRootPath << ")\n";
      if (libPath) {
        setPath << "sys.path.append(" << *libPath << ")\n";
      }
      if (venvPath) {
        // TODO(gnattishness) if venv path is provided, don't contain system
        // site packages load a venv properly instead of just modifying sys.path
        // can probably do it with exec_prefix
        setPath << "sys.path.append("
                << std::filesystem::canonical((*venvPath) / venvLibSuffix)
                << ")\n";
      }
      if (PyRun_SimpleString(setPath.str().c_str()) != 0) {
        printf("Fatal: Cannot set python PATH\n");
        PyErr_Print();
        abort();
      }
    }

    PyObject *pValue, *pModule, *pLocal;

    // TODO(gnattishness) use existing file module or __main__ and read using Py
    // API
    pModule = PyModule_New("fuzzermod");
    PyModule_AddStringConstant(pModule, "__file__", "");
    pLocal = PyModule_GetDict(pModule);
    // TODO(gnattishness) pLocal is used for *globals
    // TODO(gnattishness) why not just PyRun_File ?
    // TODO(gnattishness) try doing runfile and check the type of the pyobject
    pValue = PyRun_String(code.c_str(), Py_file_input, pLocal, pLocal);

    if (pValue == nullptr) {
      printf("Fatal: Cannot create Python function from string\n");
      PyErr_Print();
      abort();
    }
    Py_DECREF(pValue);

    // Call FuzzerInit with relevant parameters
    PyObject* initFun = PyObject_GetAttrString(pModule, "FuzzerInit");
    if (initFun == nullptr ||
        !PyCallable_Check(static_cast<PyObject*>(initFun))) {
      printf("Fatal: FuzzerInit not defined or not callable\n");
      abort();
    }
    PyObject* pArgs = PyTuple_New(1);
    int err = PyTuple_SetItem(pArgs, 0, PyBool_FromLong(bls_disabled));
    if (err) {
      printf("Fatal: Unable to add bool to init args tuple.\n");
      PyErr_Print();
      abort();
    }
    pValue = PyObject_CallObject(initFun, pArgs);
    if (pValue == nullptr) {
      // FuzzerInit() raised an exception
      printf("Fatal: FuzzerInit failed.");
      PyErr_Print();
      abort();
    }
    // Don't care about the value returned

    Py_DECREF(pValue);
    Py_DECREF(pArgs);
    Py_DECREF(initFun);

    pFunc = PyObject_GetAttrString(pModule, "FuzzerRunOne");

    if (pFunc == nullptr || !PyCallable_Check(static_cast<PyObject*>(pFunc))) {
      printf("Fatal: FuzzerRunOne not defined or not callable\n");
      abort();
    }
    if (eval_paths_rel_to_file) {
      // restore CWD
      std::filesystem::current_path(oldCwd);
    }
  }
  // TODO(gnattishness) return a ref instead of a vector by value?
  std::optional<std::vector<uint8_t>> Run(const std::vector<uint8_t>& data) {
    std::optional<std::vector<uint8_t>> ret = std::nullopt;

    if (data.empty()) {
      // Ensure data is not empty. Otherwise:
      //
      // "If size() is 0, data() may or may not return a null pointer."
      // https://en.cppreference.com/w/cpp/container/vector/data
      //
      // if nullptr, the pValue contains uninitialized data:
      // "If v is NULL, the contents of the bytes object are uninitialized."
      // https://docs.python.org/3/c-api/bytes.html?highlight=pybytes_check#c.PyBytes_FromStringAndSize
      // NOTE: this assumes empty input is never valid
      return ret;
    }
    // swap to our interpreter, don't care about previous interpreter
    // TODO(gnattishness) quicker to not swap if already at our interpreter?
    (void)PyThreadState_Swap(thisInterpreter);

    PyObject* pArgs = PyTuple_New(1);
    PyObject* pValue =
        PyBytes_FromStringAndSize((const char*)data.data(), data.size());
    if (pValue == nullptr) {
      printf("Fatal: Unable to save data as bytes\n");
      PyErr_Print();
      abort();
    }
    // NOTE: this pValue does not need to be DECREFed because PyTuple_SetItem
    // steals the reference
    int err = PyTuple_SetItem(pArgs, 0, pValue);
    if (err) {
      printf("Fatal: Unable to add bytes to a tuple.\n");
      PyErr_Print();
      abort();
    }

    pValue = PyObject_CallObject(pFunc, pArgs);

    if (pValue == nullptr) {
      // Abort on unhandled exception.
      // Indicates an error in the Python code.
      // E.g. Eth2 Py spec only specifies behaviour for AssertionError and
      // IndexError
      // https://github.com/ethereum/eth2.0-specs/blob/dev/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
      //
      // Any expected exceptions that indicate failure (but not a bug) should be
      // caught by the target function, and None returned.
      PyErr_Print();
      abort();
    }

    if (PyBytes_Check(pValue)) {
      /* Retrieve output */

      uint8_t* output;
      Py_ssize_t outputSize;
      if (PyBytes_AsStringAndSize(pValue, reinterpret_cast<char**>(&output),
                                  &outputSize) != -1) {
        /* Return output */
        ret.emplace(output, output + outputSize);
        // TODO(gnattishness) N isn't this goto irrelevant?
        goto end;
      } else {
        printf(
            "Fatal: Returning Python bytes failed - this should not happen.\n");
        abort();
      }

    } else if (pValue != Py_None) {
      printf("Fatal: unexpected return type. Should return a bytes or None");
      abort();
    }
    // We returned None

  end:
    Py_DECREF(pValue);
    Py_DECREF(pArgs);
    return ret;
  }

  ~Impl(void) {
    // TODO(gnattishness) handle whether it is the main interpreter or a sub -
    // perhaps a ref-counted object?
    // TODO(gnattishness) finalize/delete interpreter
    // Need to ensure we hold the GIL, and this is the current interpreter (swap
    // to it if it isn't)
    // Py_EndInterpreter(this
    // PyFinalizeEx()
  }
};

Python::Python(const std::string& name, const std::string& argv0,
               const std::filesystem::path& scriptPath,
               const std::optional<const std::filesystem::path>& libPath,
               const std::optional<const std::filesystem::path>& venvPath,
               const bool bls_disabled, const bool eval_paths_rel_to_file)
    : Base(),
      pimpl_{std::make_unique<Impl>(argv0, scriptPath, libPath, venvPath,
                                    bls_disabled, eval_paths_rel_to_file)} {
  name_ = name;
}

std::optional<std::vector<uint8_t>> Python::Run(
    const std::vector<uint8_t>& data) {
  return pimpl_->Run(data);
}

const std::string& Python::name() { return this->name_; }

Python::~Python() = default;

} /* namespace fuzzing */
