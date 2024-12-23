package dashboardserver

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"mqttmtd/config"
	"mqttmtd/types"
	"net/http"
	"sort"
	"strconv"
	"time"
	"unsafe"
)

type TableData struct {
	Headers []string
	Rows    [][]string
}

const pageTemplate = `
<!DOCTYPE html>
<html>
<head>
	<title>Authserver Current Status</title>
	<style>
		body {
			width: 90%;
			margin: auto;
		}
		table {
			width: 100%;
			border-collapse: collapse;
			margin: 20px 0;
		}
		th, td {
			border: 1px solid #ddd;
			padding: 8px;
		}
		th {
			background-color: #f2f2f2;
			text-align: left;
		}
	</style>
</head>
<body>
	<h1>Authserver Current Status ({{.Timestamp}})</h1>
	<h2>Access Control List</h2>
	<table>
		<tr>
			{{range .ACL.Headers}}
				<th>{{.}}</th>
			{{end}}
		</tr>
		{{range .ACL.Rows}}
			<tr>
				{{range .}}
					<td>{{.}}</td>
				{{end}}
			</tr>
		{{end}}
	</table>

	<h2>Auth Token List</h2>
	<table>
		<tr>
			{{range .ATL.Headers}}
				<th>{{.}}</th>
			{{end}}
		</tr>
		{{range .ATL.Rows}}
			<tr>
				{{range .}}
					<td>{{.}}</td>
				{{end}}
			</tr>
		{{end}}
	</table>
</body>
</html>
`

var (
	myAcl *types.AccessControlList
	myAtl *types.AuthTokenList
)

func Run(acl *types.AccessControlList, atl *types.AuthTokenList) {
	myAcl = acl
	myAtl = atl
	http.HandleFunc("/", httpServerHandler)
	fmt.Println("Starting dashboard server on port ", config.Server.Ports.Dashboard)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", config.Server.Ports.Dashboard), nil); err != nil {
		fmt.Println("Error starting server: ", err)
	}
}

func httpServerHandler(w http.ResponseWriter, req *http.Request) {
	var (
		aclTbl *TableData = &TableData{}
		atlTbl *TableData = &TableData{}
	)
	myAcl.Lock()
	func() {
		defer myAcl.Unlock()

		aclTbl.Headers = []string{"CLIENT_NAME", "TOPIC", "ACCESS_TYPE"}
		aclTbl.Rows = [][]string{}
		sortedClientNames := make([]string, 0, len(myAcl.Entries))
		for k := range myAcl.Entries {
			sortedClientNames = append(sortedClientNames, k)
		}
		sort.Strings(sortedClientNames)
		for _, clientName := range sortedClientNames {
			permittedAccessDict := myAcl.Entries[clientName]
			sortedTopics := make([]string, 0, len(permittedAccessDict))
			for k := range permittedAccessDict {
				sortedTopics = append(sortedTopics, k)
			}
			sort.Strings(sortedTopics)
			for _, topic := range sortedTopics {
				accessType := permittedAccessDict[topic]
				newRow := []string{
					clientName,
					topic,
					accessType.String(),
				}
				aclTbl.Rows = append(aclTbl.Rows, newRow)
			}
		}
	}()

	myAtl.Lock()
	func() {
		defer myAtl.Unlock()

		atlTbl.Headers = []string{"INDEX", "TIMESTAMP", "CURRENT_VALID_RANDOM_DATA", "CUR_RANDOM_DATA_INDEX", "CLIENT_NAME", "ACCESS_TYPE", "TOPIC"}
		atlTbl.Rows = [][]string{}
		myAtl.ForEachEntry(func(i int, entry *types.ATLEntry) {
			var accessTypeStr string
			if entry.AccessTypeIsPub {
				accessTypeStr = "Pub"
			} else {
				accessTypeStr = "Sub"
			}
			newRow := []string{
				strconv.FormatInt(int64(i)+1, 10),
				fmt.Sprintf("%02X-%s", entry.Timestamp[0], hex.EncodeToString(entry.Timestamp[1:])),
				hex.EncodeToString(entry.CurrentValidRandomData[:]),
				strconv.FormatInt(int64(entry.CurrentValidTokenIdx), 10),
				unsafe.String(unsafe.SliceData(entry.ClientName), len(entry.ClientName)),
				accessTypeStr,
				unsafe.String(unsafe.SliceData(entry.Topic), len(entry.Topic)),
			}
			atlTbl.Rows = append(atlTbl.Rows, newRow)
		})
	}()

	// Parse and execute the template
	tmpl := template.Must(template.New("page").Parse(pageTemplate))
	if err := tmpl.Execute(w, map[string]interface{}{"Timestamp": time.Now().Local().Format(time.Stamp), "ACL": *aclTbl, "ATL": *atlTbl}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
