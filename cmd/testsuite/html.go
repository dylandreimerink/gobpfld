package main

import (
	"fmt"
	"html/template"
	"io"
	"sort"

	"github.com/dylandreimerink/gobpfld/kernelsupport"
)

func renderHTMLReport(testResults map[string]map[string]testResult, out io.Writer) error {
	tpl := template.New("report")

	var err error
	tpl, err = tpl.Parse(htmlTpl)
	if err != nil {
		return fmt.Errorf("parse tpl: %w", err)
	}

	envs := make([]string, 0, len(testResults))
	for k := range testResults {
		envs = append(envs, k)
	}

	// Sort environments from oldest to newest
	sort.Slice(envs, func(i, j int) bool {
		iV, err := kernelsupport.ParseKernelVersion(availableEnvs[envs[i]].kernel, true)
		if err != nil {
			panic(err)
		}

		jV, err := kernelsupport.ParseKernelVersion(availableEnvs[envs[j]].kernel, true)
		if err != nil {
			panic(err)
		}

		return jV.Higher(iV)
	})

	testsMap := make(map[string]bool)
	for _, t := range testResults {
		for testName := range t {
			testsMap[testName] = true
		}
	}

	tests := make([]string, len(testsMap))
	i := 0
	for testsMap := range testsMap {
		tests[i] = testsMap
		i++
	}
	sort.Strings(tests)

	err = tpl.Execute(out, htmlData{
		Envs:         envs,
		Tests:        tests,
		TestResults:  testResults,
		FlagCoverage: flagCover,
	})
	if err != nil {
		return fmt.Errorf("execute tpl: %w", err)
	}

	return nil
}

type htmlData struct {
	Envs         []string
	Tests        []string
	TestResults  map[string]map[string]testResult
	FlagCoverage bool
}

var htmlTpl = `<html>
	<head>
		<title>GoBPFLD test report</title>
		<style>
			.test-matrix {
				border-spacing: 0px;
			}

			.test-matrix td {
				padding: 4px;
				border-width: 1px 0px 0px 0px;
				border-style: solid;
			}

			.test-matrix td.result {
				border-width: 1px 0px 0px 1px;
			}

			td.PASS {
				background-color: #50CC50;
			}

			td.FAIL {
				background-color: #FF3333;
			}

			td.SKIP {
				background-color: #FFC107;
			}

			td.UNTESTED {
				background-color: #BDBDBD;
			}
		</style>
	</head>
	<body>
		<h1>GoBPFLD test report</h1>
		<div>
			<h2>Test matrix</h2>
			<table class="test-matrix">
				<thead>
					<tr>
						<th>Test name</th>
					{{range $i, $env := .Envs}}
						<th>{{$env}}</th>
					{{end}}
					</tr>
				<thead>
				<tbody>
				{{range $i, $test := .Tests}}
					<tr>
						<td>{{$test}}</td>
					{{range $ii, $env := $.Envs}}
					{{with $res := index (index $.TestResults $env) $test}}
						<td class="{{$res.Status}} result">{{$res.Status}}</td>
					{{end}}
					{{end}}
					</tr>
				{{end}}
				</tbody>
			</table>
		</div>
		<div>
			<h2>Code coverage per env</h2>
			<ul>
			{{range $i, $env := .Envs}}
				<li><a href="./{{$env}}/gobpfld.cover.html">{{$env}}</a></li>
			{{end}}
			</ul>
		</div>
	</body>
</html>`
