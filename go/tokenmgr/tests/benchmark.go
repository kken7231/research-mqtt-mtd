package main

import (
	"flag"
	"fmt"
	"log"
	"mqttmtd/tokenmgr/tests/t01gettoken"
	"mqttmtd/tokenmgr/tests/t02publish"
	"mqttmtd/tokenmgr/tests/t03subscribe"
	"mqttmtd/tokenmgr/tests/testutil"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

// pushd ../../certcreate; ./generate_certs.sh -c ../certs; popd
// go test -x -run ^$ -benchmem -count 1000 -bench .

var (
	t01Benchmarks = t01gettoken.Benchmarks
	t02Benchmarks = t02publish.Benchmarks
	t03Benchmarks = t03subscribe.Benchmarks
)

func main() {
	test := flag.Int("test", 1, "Test index")
	iter := flag.Int("iter", 10, "Iteration of benchmarks")
	numTokens := flag.Int("nt", 12, "Number of Tokens per fetch")
	filter := flag.String("filter", ".", "Regex to filter benchmarks")
	testing.Init()
	flag.Set("test.benchtime", "1x")
	flag.Parse()

	testutil.SetNumTokens(uint16(*numTokens))
	var benchmarkFuncs []func(*testing.B)
	switch *test {
	case 1:
		benchmarkFuncs = t01Benchmarks
	case 2:
		benchmarkFuncs = t02Benchmarks
	case 3:
		benchmarkFuncs = t03Benchmarks
	default:
		log.Fatal("Illegal test index")
	}

	re, err := regexp.Compile(*filter)
	if err != nil {
		fmt.Println("Error compiling regex:", err)
		return
	}
	startExcluded := len(benchmarkFuncs)
	for i := 0; i < startExcluded; {
		rv := reflect.ValueOf(benchmarkFuncs[i])
		splittedFuncName := strings.Split(runtime.FuncForPC(rv.Pointer()).Name(), ".Benchmark")
		funcName := splittedFuncName[len(splittedFuncName)-1]
		if !re.Match(unsafe.Slice(unsafe.StringData(funcName), len(funcName))) {
			temp := benchmarkFuncs[startExcluded-1]
			benchmarkFuncs[startExcluded-1] = benchmarkFuncs[i]
			benchmarkFuncs[i] = temp
			startExcluded--
		} else {
			i++
		}
	}
	benchmarkFuncs = benchmarkFuncs[:startExcluded]
	res := testutil.RunBenchmarks(*iter, benchmarkFuncs...)
	testutil.PrintResults(res)
}
