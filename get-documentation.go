// OBP Get Documentation

// This script exercises the Resource Doc (and soon, Glossary) endpoints.

// Run with:
// go run get-documentation.go -obpapihost http://127.0.0.1:8080 -username YOUR USERNAME -password haGdju%YOUR PASSWORD -consumer YOUR CONSUMER KEY -maxOffsetMetrics 5 -maxLimitMetrics 5 -apiexplorerhost https://apiexplorer-ii-sandbox.openbankproject.com -loopResourceDocs 10 -printResourceDocs 1

// This script will print your user_id as a helper.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	obp "github.com/tawoe/obp-go-sdk"
)

// declaring a struct
type DirectLoginToken struct {
	// defining struct variables note: struct needs Proper case field names
	Token string `json:"token"`
}

type CurrentUserId struct {
	UserId string `json:"user_id"`
}

type Entitlement struct {
	BankID   string `json:"bank_id"`
	RoleName string `json:"role_name"`
}

type HostedBy struct {
	Organisation        string `json:"organisation"`
	Email               string `json:"email"`
	Phone               string `json:"phone"`
	OrganisationWebsite string `json:"organisation_website"`
}

type HostedAt struct {
	Organisation        string `json:"organisation"`
	OrganisationWebsite string `json:"organisation_website"`
}

type EnergySource struct {
	Organisation        string `json:"organisation"`
	OrganisationWebsite string `json:"organisation_website"`
}

type root struct {
	Version                  string       `json:"version"`
	VersionStatus            string       `json:"version_status"`
	GitCommit                string       `json:"git_commit"`
	Stage                    string       `json:"stage"`
	Connector                string       `json:"connector"`
	Hostname                 string       `json:"hostname"`
	LocalIdentityProvider    string       `json:"local_identity_provider"`
	HostedBy                 HostedBy     `json:"hosted_by"`
	HostedAt                 HostedAt     `json:"hosted_at"`
	EnergySource             EnergySource `json:"energy_source"`
	ResourceDocsRequiresRole bool         `json:"resource_docs_requires_role"`
}

type ImplementedBy struct {
	Version  string `json:"version"`
	Function string `json:"function"`
}

type ExampleRequestBody struct {
	JsonString string `json:"jsonString"`
}

type SuccessResponseBody struct {
	JsonString string `json:"jsonString"`
}

type TypedRequestBody struct {
	Type       string `json:"type"`
	Properties struct {
		JsonString struct {
			Type string `json:"type"`
		} `json:"properties"`
	} `json:"properties"`
}

type TypedSuccessResponseBody struct {
	Type       string `json:"type"`
	Properties struct {
		JsonString struct {
			Type string `json:"type"`
		} `json:"properties"`
	} `json:"properties"`
}

type Role struct {
	Role           string `json:"role"`
	RequiresBankID bool   `json:"requires_bank_id"`
}

type ResourceDoc struct {
	OperationID         string        `json:"operation_id"`
	ImplementedBy       ImplementedBy `json:"implemented_by"`
	RequestVerb         string        `json:"request_verb"`
	RequestURL          string        `json:"request_url"`
	Summary             string        `json:"summary"`
	Description         string        `json:"description"`
	DescriptionMarkdown string        `json:"description_markdown"`
	//ExampleRequestBody  ExampleRequestBody `json:"example_request_body"`
	//SuccessResponseBody      SuccessResponseBody      `json:"success_response_body"`
	ErrorResponseBodies      []string                 `json:"error_response_bodies"`
	Tags                     []string                 `json:"tags"`
	TypedRequestBody         TypedRequestBody         `json:"typed_request_body"`
	TypedSuccessResponseBody TypedSuccessResponseBody `json:"typed_success_response_body"`
	Roles                    []Role                   `json:"roles"`
	IsFeatured               bool                     `json:"is_featured"`
	SpecialInstructions      string                   `json:"special_instructions"`
	SpecifiedURL             string                   `json:"specified_url"`
	ConnectorMethods         []interface{}            `json:"connector_methods"`
}

type ResourceDocs struct {
	ResourceDocs []ResourceDoc `json:"resource_docs"`
}

/////

// //////// Swagger related //////////////////
type Info struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type Property struct {
	Type    string `json:"type"`
	Example string `json:"example"`
}

type BankAccount struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
}

type Responses struct {
	Description string `json:"description"`
	Schema      struct {
		Ref string `json:"$ref"`
	} `json:"schema"`
}

type PathItem struct {
	OperationId string   `json:"operationId"`
	Produces    []string `json:"produces"`
	Responses   map[string]Responses
	Consumes    []string `json:"consumes"`
	Description string   `json:"description"`
	Summary     string   `json:"summary"`
}

type Swagger struct {
	Swagger     string                 `json:"swagger"`
	Info        Info                   `json:"info"`
	Definitions map[string]BankAccount `json:"definitions"`
	Paths       map[string]map[string]PathItem
	Host        string   `json:"host"`
	Schemes     []string `json:"schemes"`
}

func getSwagger(modifier string) Swagger {

	// Create Info struct
	info := Info{
		Title:   fmt.Sprintf("Bank Accounts (Dynamic Endpoint) %s", modifier),
		Version: "1.0.0",
	}

	// Create BankAccount struct
	bankAccount := BankAccount{
		Type: "object",
		Properties: map[string]Property{
			"account_name": {
				Type:    "string",
				Example: "family account",
			},
			"account_balance": {
				Type:    "string",
				Example: "1000.01",
			},
		},
	}

	// Create Responses struct
	responses := Responses{
		Description: "Success Response",
		Schema: struct {
			Ref string `json:"$ref"`
		}{
			Ref: "#/definitions/AnAccount",
		},
	}

	// Create PathItem struct for POST /accounts
	postAccount := PathItem{
		OperationId: fmt.Sprintf("%s_%s", modifier, "POST_account"),
		Produces:    []string{"application/json"},
		Responses: map[string]Responses{
			"201": responses,
		},
		Consumes:    []string{"application/json"},
		Description: "POST Accounts",
		Summary:     "POST Accounts",
	}

	// Create PathItem struct for GET /accounts/{account_id}
	getAccount := PathItem{
		OperationId: fmt.Sprintf("%s_%s", modifier, "GET_account"),
		Produces:    []string{"application/json"},
		Responses: map[string]Responses{
			"200": responses,
		},
		Consumes:    []string{"application/json"},
		Description: "Get Bank Account",
		Summary:     "Get Bank Account by Id",
	}

	// Create Paths map
	paths := map[string]map[string]PathItem{
		fmt.Sprintf("/%s%s", modifier, "/accounts"): {
			"post": postAccount,
		},
		fmt.Sprintf("/%s%s", modifier, "/accounts/{account_id}"): {
			"get": getAccount,
		},
	}

	// Create Swagger struct
	mySwagger := Swagger{
		Swagger: "2.0",
		Info:    info,
		Definitions: map[string]BankAccount{
			"AnAccount": bankAccount,
		},
		Paths:   paths,
		Host:    "obp_mock",
		Schemes: []string{"http", "https"},
	}

	return mySwagger

}

// End Swagger related /////////////////////////////

/*

{
    "resource_docs": [
        {
            "operation_id": "OBPv1.4.0-testResourceDoc",
            "implemented_by": {
                "version": "OBPv1.4.0",
                "function": "testResourceDoc"
            },
            "request_verb": "GET",
            "request_url": "/dummy",
            "summary": "Test Resource Doc",
            "description": "<p>I am only a test Resource Doc</p>\n<p>Authentication is Mandatory</p>\n<p><strong>JSON response body fields:</strong></p>\n",
            "description_markdown": "I am only a test Resource Doc\n\nAuthentication is Mandatory\n\n\n**JSON response body fields:**\n\n\n",
            "example_request_body": {
                "jsonString": "{}"
            },
            "success_response_body": {
                "jsonString": "{}"
            },
            "error_response_bodies": [
                "OBP-50000: Unknown Error.",
                "OBP-20001: User not logged in. Authentication is required!",
                "OBP-20006: User is missing one or more roles: "
            ],
            "tags": [
                "Documentation"
            ],
            "typed_request_body": {
                "type": "object",
                "properties": {
                    "jsonString": {
                        "type": "string"
                    }
                }
            },
            "typed_success_response_body": {
                "type": "object",
                "properties": {
                    "jsonString": {
                        "type": "string"
                    }
                }
            },
            "roles": [
                {
                    "role": "CanGetCustomers",
                    "requires_bank_id": true
                }
            ],
            "is_featured": false,
            "special_instructions": "",
            "specified_url": "",
            "connector_methods": []
        }
    ]
}

*/

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func main() {

	rand.Seed(time.Now().UnixNano())

	var obpApiHost string
	var username string
	var password string
	var consumerKey string
	var apiExplorerHost string

	var maxOffsetMetrics int
	var maxLimitMetrics int

	var loopResourceDocs int

	var tags string
	var printResourceDocs int

	flag.StringVar(&obpApiHost, "obpapihost", "YOUR OBP HOST", "Provide an OBP host to test (include the protocol and port)")
	flag.StringVar(&username, "username", "YOUR USERNAME", "Username to access the service with")
	flag.StringVar(&password, "password", "YOUR PASSWORD", "Provide your password")
	flag.StringVar(&consumerKey, "consumer", "YOUR CONSUMER KEY", "Provide your consumer key")
	flag.StringVar(&apiExplorerHost, "apiexplorerhost", "API EXPLORER II HOST", "Provide API Explorer II for documentation links ")
	flag.StringVar(&tags, "tags", "", "Provide Resource Doc tags")

	flag.IntVar(&maxOffsetMetrics, "maxOffsetMetrics", 10, "Provide your maxOffsetMetrics")
	flag.IntVar(&maxLimitMetrics, "maxLimitMetrics", 5, "Provide your maxLimitMetrics")

	flag.IntVar(&loopResourceDocs, "loopResourceDocs", 5, "Provide your loopResourceDocs")

	flag.IntVar(&printResourceDocs, "printResourceDocs", 0, "Print the found Resource Docs (1) or not (0)")

	flag.Parse()

	fmt.Printf("I'm using the following values for -obpapihost -username -password -consumer -maxOffsetMetrics -maxLimitMetrics -apiexplorerhost -loopResourceDocs -printResourceDocs \n")
	fmt.Println(obpApiHost)
	fmt.Println(username)
	fmt.Println(password)
	fmt.Println(consumerKey)

	fmt.Println(maxOffsetMetrics)
	fmt.Println(maxLimitMetrics)

	fmt.Println(apiExplorerHost)

	fmt.Println(loopResourceDocs)

	fmt.Println(printResourceDocs)

	// Get a DirectLogin token with our credentials
	myToken, dlTokenError := getDirectLoginToken(obpApiHost, username, password, consumerKey)

	if dlTokenError == nil {
		fmt.Printf("DirectLogin token i got: %s\n", myToken)

		myRoot, errRoot := getRoot(obpApiHost, myToken)

		if errRoot == nil {
			fmt.Printf("gitCommitOfApi is: %s\n", myRoot.GitCommit)
		} else {
			fmt.Printf("errRoot: %s\n", errRoot)
		}

		err := writeResourceDocs("resource-docs", obpApiHost, "v3.0.0", "OBP", myToken)
		if err != nil {
			log.Printf("error writing resource docs: %s", err)
		}

		//createEntitlements(obpApiHost, myToken)

		//getVariousResourceDocs(obpApiHost, myToken, apiExplorerHost, tags, loopResourceDocs, printResourceDocs)

		//getDynamicMessageDocs(obpApiHost, myToken, loopResourceDocs, apiExplorerHost)

	} else {
		fmt.Printf("Hmm, getDirectLoginToken returned an error: %s - I will stop now. \n", dlTokenError)
	}

}

func writeResourceDocs(dirname string, obpApiHost string, apiVersion string, standard string, token string) error {
	// create the server's http client for obp
	client_conf := obp.Configuration{
		BasePath:      obpApiHost,
		DefaultHeader: make(map[string]string),
		UserAgent:     "golang-get-documentation",
	}
	client_conf.AddDefaultHeader("Authorization", fmt.Sprintf("DirectLogin token=%s", token))
	client_conf.AddDefaultHeader("Content-type", "application/json")
	client := obp.NewAPIClient(&client_conf)

	if standard == "swagger" {
		docs, resp, err := client.APIApi.GetResourceDocsSwagger(context.Background(), obp.EmptyClassJson{}, apiVersion)

		if err != nil {
			responseBody, resperr := io.ReadAll(resp.Body)
			if resperr != nil {
				log.Printf("Error reading response body: %s", resperr)
			}
			log.Printf("writeResourceDocs error: %s, Response Body: %s", err, responseBody)
		}

		jsonDocs, err := json.Marshal(docs)
		if err != nil {
			log.Printf("writeResourceDocs error, error marshalling docs: %s", err)
		}

		// Create directory
		dir := filepath.Join(".", dirname)
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			log.Printf("error creating directory: %s", err)
		}

		// Write to json file
		path := filepath.Join(".", dirname, "ResourceDocsSwagger.json")
		err = os.WriteFile(path, jsonDocs, 0644)
		if err != nil {
			log.Printf("writeResourceDocs error, could not write to file \"%s\": %s", path, err)
		}

	} else if standard == "OBP" {
		docs, resp, err := client.APIApi.GetResourceDocsObpV400(context.Background(), obp.EmptyClassJson{}, apiVersion)
		log.Print(docs)
		//log.Printf("%#v", docs)
		if err != nil {
			responseBody, resperr := io.ReadAll(resp.Body)
			if resperr != nil {
				log.Printf("Error reading response body: %s", resperr)
			}
			log.Printf("writeResourceDocs error: %s, Response Body: %s", err, responseBody)
		}

		jsonDocs, err := json.Marshal(docs)
		if err != nil {
			log.Printf("writeResourceDocs error, error marshalling docs: %s", err)
		}

		// Create directory
		dir := filepath.Join(".", dirname)
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			log.Printf("error creating directory: %s", err)
		}

		// Write to json file
		path := filepath.Join(".", dirname, "ResourceDocs.json")
		err = os.WriteFile(path, jsonDocs, 0644)
		if err != nil {
			log.Printf("writeResourceDocs error, could not write to file \"%s\": %s", path, err)
		}

	} else {
		log.Printf("error, unknown standard \"%s\", supported standards are \"swagger\" or \"OBP\"", standard)
	}

	return nil
}

func getVariousResourceDocs(obpApiHost string, myToken string, apiExplorerHost string, tags string, loopResourceDocs int, printResourceDocs int) {
	for i := 1; i <= loopResourceDocs; i++ {
		myRDCount, myRDError := getResourceDocs(obpApiHost, myToken, i, "static", apiExplorerHost, tags, printResourceDocs)

		if myRDError == nil {
			fmt.Printf("we got %d resource docs \n", myRDCount)
		} else {
			fmt.Printf("we got error %s getting resource docs \n", myRDError)
		}

		if myRDError == nil {
			fmt.Printf("we got %d resource docs \n", myRDCount)
		} else {
			fmt.Printf("we got error %s getting resource docs\n", myRDError)
		}

		myRDCount, myRDError = getResourceDocs(obpApiHost, myToken, i, "dynamic", apiExplorerHost, tags, printResourceDocs)

		if myRDError == nil {
			fmt.Printf("we got %d resource docs\n", myRDCount)
		} else {
			fmt.Printf("we got error %s getting resource docs\n", myRDError)
		}

		if myRDError == nil {
			fmt.Printf("we got %d resource docs\n", myRDCount)
		} else {
			fmt.Printf("we got error %s getting resource docs\n", myRDError)
		}

		myRDCount, myRDError = getResourceDocs(obpApiHost, myToken, i, "all", apiExplorerHost, tags, printResourceDocs)

		if myRDError == nil {
			fmt.Printf("we got %d resource docs\n", myRDCount)
		} else {
			fmt.Printf("we got error %s getting resource docs\n", myRDError)
		}
	}

}

func getDirectLoginToken(obpApiHost string, username string, password string, consumerKey string) (string, error) {

	// defining a struct instance, we will put the token in this.
	var directLoginToken1 DirectLoginToken

	// Create client
	client := &http.Client{}

	// Create request path
	requestURL := fmt.Sprintf("%s/my/logins/direct", obpApiHost)

	// Nothing in the body
	req, err1 := http.NewRequest("POST", requestURL, nil)

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("username=%s, password=%s, consumer_key=%s", username, password, consumerKey)},
	}

	// Do the Request
	resp, err1 := client.Do(req)

	if err1 == nil {
		fmt.Println("We got a response from the http server. Will check Response Status Code...")
	} else {
		fmt.Println("We failed making the http request: ", err1)
		return "", err1
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 201 {
		fmt.Printf("We got a 201 Response: %d \n", resp.StatusCode)
	} else {
		fmt.Printf("Hmm, Non ideal Response Status : %s \n", resp.Status)
		fmt.Printf("Response Body : %s \n", string(respBody))
		return "", errors.New("Non 201 Response")
	}

	//fmt.Println("response Headers : ", resp.Header)

	// assuming respBody is the JSON equivelent of DirectLoginToken, put it in directLoginToken1
	err2 := json.Unmarshal(respBody, &directLoginToken1)

	if err2 == nil {
		//fmt.Printf("I will return this token: %s \n", directLoginToken1.Token)
		return directLoginToken1.Token, nil
	} else {
		fmt.Printf("Struct instance is: %s", directLoginToken1)
		fmt.Printf("token is %s \n", directLoginToken1.Token)
		return "", err2
	}

}

func getUserId(obpApiHost string, token string) (string, error) {

	fmt.Printf("Hello from getUserId. obpApiHost is: %s token is %s \n", obpApiHost, token)

	// Create client
	client := &http.Client{}

	// defining a struct instance, we will put the token in this.
	var currentUserId CurrentUserId

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/users/current/user_id", obpApiHost)

	req, erry := http.NewRequest("GET", requestURL, nil)
	if erry != nil {
		fmt.Println("Failure constructing NewRequest: ", erry)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	// Fetch Request
	resp, err1 := client.Do(req)

	if err1 != nil {
		fmt.Println("***** Failure trying to get user_id: ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	//fmt.Println("getUserId response Status : ", resp.Status)
	//fmt.Println("response Headers : ", resp.Header)
	//fmt.Println("getUserId response Body : ", string(respBody))

	// assuming respBody is the JSON equivelent of DirectLoginToken, put it in directLoginToken1
	err2 := json.Unmarshal(respBody, &currentUserId)

	if err2 != nil {
		fmt.Println(err2)
	}

	//fmt.Println("Struct instance for currentUserId is:", currentUserId)
	//fmt.Printf("UserId is %s \n", currentUserId.UserId)

	return currentUserId.UserId, err2

}

//

func createEntitlements(obpApiHost string, token string) error {

	//fmt.Printf("token i will use: %s\n", token)
	// We need the User ID to grant entitlements.
	userId, error := getUserId(obpApiHost, token)

	if error == nil {
		fmt.Printf("userId is: %s \n", userId)
		// If we are a super user we can grant ourselves this
		error := createEntitlement(obpApiHost, token, userId, "", "CanCreateEntitlementAtAnyBank")
		// Then with the above role we can grant ourselves other roles
		if error == nil {
			error := createEntitlement(obpApiHost, token, userId, "", "CanReadMetrics")
			if error == nil {
				error := createEntitlement(obpApiHost, token, userId, "", "CanReadAggregateMetrics")
				if error == nil {
					error := createEntitlement(obpApiHost, token, userId, "", "CanCreateDynamicEndpoint")
					if error == nil {
						error := createEntitlement(obpApiHost, token, userId, "", "CanGetAllDynamicMessageDocs")
						if error == nil {
							error := createEntitlement(obpApiHost, token, userId, "", "CanCreateDynamicMessageDoc")
							if error == nil {
								fmt.Println("createEntitlements says: No errors")
							} else {
								fmt.Printf("createEntitlements says error: %s\n", error)
							}
						} else {
							fmt.Printf("createEntitlements says error: %s\n", error)
						}
					} else {
						fmt.Printf("createEntitlements says error: %s\n", error)
					}
				} else {
					fmt.Printf("createEntitlements says error: %s\n", error)
				}
			} // note these missing message on error
		}
	}

	//

	return error

}

func createEntitlement(obpApiHost string, token string, userID string, bankId string, roleName string) error {

	// Create client
	client := &http.Client{}

	// Create request

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/users/%s/entitlements", obpApiHost, userID)

	entitlement := Entitlement{
		BankID:   bankId,
		RoleName: roleName,
	}
	// marshall data to json (like json_encode)
	marshalledEntitlement, err := json.Marshal(entitlement)
	if err != nil {
		fmt.Printf("impossible to marshall entitlement: %s", err)
	}

	req, errx := http.NewRequest("POST", requestURL, bytes.NewReader(marshalledEntitlement))

	if errx != nil {
		fmt.Println("Failure : ", errx)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	// Fetch Request
	resp, err1 := client.Do(req)

	if err1 != nil {
		fmt.Println("Failure : ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	fmt.Println("response Status : ", resp.Status)
	//fmt.Println("response Headers : ", resp.Header)
	fmt.Println("response Body : ", string(respBody))

	return err1

}

func getRoot(obpApiHost string, token string) (root, error) {

	fmt.Printf("Hello from getRoot. obpApiHost is: %s token is %s \n", obpApiHost, token)

	// Create client
	client := &http.Client{}

	// defining a struct instance, we will put the token in this.
	var myRoot root

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/root", obpApiHost)
	//requestURL := fmt.Sprintf("%s/obp/v5.1.0/users/current", obpApiHost)

	req, erry := http.NewRequest("GET", requestURL, nil)
	if erry != nil {
		fmt.Println("Failure constructing NewRequest: ", erry)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	// Fetch Request
	resp, err1 := client.Do(req)

	if err1 != nil {
		fmt.Println("***** Failure trying to getRoot: ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// assuming respBody is the JSON equivelent of DirectLoginToken, put it in directLoginToken1
	err2 := json.Unmarshal(respBody, &myRoot)

	if err2 != nil {
		fmt.Println(err2)
		fmt.Println("Struct instance for myRoot is:", myRoot)
	} else {
		// fmt.Printf("GitCommit is %s \n", myRoot.GitCommit)
	}

	fmt.Printf("------ Here are the Response Headers for : %s -------- \n", requestURL)
	for k, v := range resp.Header {
		fmt.Print(k)
		fmt.Print(" : ")
		fmt.Println(v)
	}
	fmt.Println("------- End of Response Headers --------")

	return myRoot, err2

}

func sortResourceDocs(rds ResourceDocs) (ResourceDocs, error) {
	sort.Slice(rds.ResourceDocs, func(i, j int) bool {
		return rds.ResourceDocs[i].Summary < rds.ResourceDocs[j].Summary
	})
	return rds, nil
}

func sortResourceDocsByID(docs *ResourceDocs) (ResourceDocs, error) {
	// Define a custom sorting function
	less := func(i, j int) bool {
		return docs.ResourceDocs[i].OperationID < docs.ResourceDocs[j].OperationID
	}

	// Sort the ResourceDocs using the custom sorting function
	sort.Slice(docs.ResourceDocs, less)

	return *docs, nil
}

func getResourceDocs(obpApiHost string, token string, tryCount int, content string, apiExplorerHost string, tags string, printResourceDocs int) (int, error) {

	fmt.Println("Hello from getResourceDocs. Using obpApiHost: ", obpApiHost)

	// Create client
	client := &http.Client{}

	// defining a struct instance, we will put the token in this.
	var myResourceDocs ResourceDocs

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/resource-docs/OBPv5.1.0/obp?tags=%s&content=%s", obpApiHost, tags, content)

	fmt.Println("requestURL : ", requestURL)

	req, erry := http.NewRequest("GET", requestURL, nil)
	if erry != nil {
		fmt.Println("Failure : ", erry)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	before := time.Now()

	// Fetch Request
	resp, err1 := client.Do(req)

	after := time.Now()

	duration := after.Sub(before)

	if err1 != nil {
		fmt.Println("***** Failure when getting Resource Docs: ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	fmt.Println("getResourceDocs response Status : ", resp.Status)

	fmt.Println(fmt.Sprintf("getResourceDocs response Status was %s, duration was %s, tryCount was %d, content was %s ", resp.Status, duration, tryCount, content))

	if resp.StatusCode != 200 {
		fmt.Println("getResourceDocs response Body : ", string(respBody))
		fmt.Println(fmt.Sprintf("tryCount was %d", tryCount))
		fmt.Println(fmt.Sprintf("content was %s", content))
	}

	err2 := json.Unmarshal(respBody, &myResourceDocs)

	if err2 != nil {
		fmt.Println(err2)
	}

	// sort here

	sortedResourceDocs, err3 := sortResourceDocsByID(&myResourceDocs)

	if err3 != nil {
		fmt.Println(err3)
	}

	/* Example data for testing


	jsonData := `{
	    "resource_docs": [
	        {
	            "operation_id": "OBPv1.4.0-testResourceDoc",
	            "implemented_by": {
	                "version": "OBPv1.4.0",
	                "function": "testResourceDoc"
	            },
	            "request_verb": "GET",
	            "request_url": "/dummy",
	            "summary": "Test Resource Doc",
	            "description": "<p>I am only a test Resource Doc</p>\n<p>Authentication is Mandatory</p>\n<p><strong>JSON response body fields:</strong></p>\n",
	            "description_markdown": "I am only a test Resource Doc\n\nAuthentication is Mandatory\n\n\n**JSON response body fields:**\n\n\n",
	            "example_request_body": {
	                "jsonString": "{}"
	            },
	            "success_response_body": {
	                "jsonString": "{}"
	            },
	            "error_response_bodies": [
	                "OBP-50000: Unknown Error.",
	                "OBP-20001: User not logged in. Authentication is required!",
	                "OBP-20006: User is missing one or more roles: "
	            ],
	            "tags": [
	                "Documentation"
	            ],
	            "typed_request_body": {
	                "type": "object",
	                "properties": {
	                    "jsonString": {
	                        "type": "string"
	                    }
	                }
	            },
	            "typed_success_response_body": {
	                "type": "object",
	                "properties": {
	                    "jsonString": {
	                        "type": "string"
	                    }
	                }
	            },
	            "roles": [
	                {
	                    "role": "CanGetCustomers",
	                    "requires_bank_id": true
	                }
	            ],
	            "is_featured": false,
	            "special_instructions": "",
	            "specified_url": "",
	            "connector_methods": []
	        }
	    ]
	}`
	*/

	if printResourceDocs == 1 { // Trying to use bool here was ugly

		for i := 0; i < len(sortedResourceDocs.ResourceDocs); i++ {
			//fmt.Printf(" OperationID: %s Summary: %s \n", myResourceDocs.ResourceDocs[i].OperationID, myResourceDocs.ResourceDocs[i].Summary)

			fmt.Printf("[%s](%s/operationid/%s)\n", sortedResourceDocs.ResourceDocs[i].Summary, apiExplorerHost, sortedResourceDocs.ResourceDocs[i].OperationID)
		}

	}
	// obpApiExplorerHost

	// https://apiexplorer-ii-sandbox.openbankproject.com/operationid/OBPv4.0.0-getBankLevelEndpointTags?version=OBPv5.1.0

	return len(sortedResourceDocs.ResourceDocs), nil

}

// Define a struct to match the JSON structure
type DynamicMessage struct {
	OutboundAvroSchema     string      `json:"outbound_avro_schema"`
	InboundAvroSchema      string      `json:"inbound_avro_schema"`
	AdapterImplementation  string      `json:"adapter_implementation"`
	DynamicMessageDocID    string      `json:"dynamic_message_doc_id"`
	Description            string      `json:"description"`
	Process                string      `json:"process"`
	OutboundTopic          string      `json:"outbound_topic"`
	MethodBody             string      `json:"method_body"`
	MessageFormat          string      `json:"message_format"`
	ExampleOutboundMessage struct{}    `json:"example_outbound_message"`
	InboundTopic           string      `json:"inbound_topic"`
	ExampleInboundMessage  struct{}    `json:"example_inbound_message"`
	BankID                 interface{} `json:"bank_id"`
	ProgrammingLang        string      `json:"programming_lang"`
}

type DynamicMessages struct {
	DynamicMessageDocs []DynamicMessage `json:"dynamic-message-docs"`
}

func getDynamicMessageDocs(obpApiHost string, token string, tryCount int, apiExplorerHost string) (int, error) {

	fmt.Println("Hello from getDynamicMessageDocs. Using obpApiHost: ", obpApiHost)

	// Create client
	client := &http.Client{}

	// defining a struct instance, we will put the token in this.
	var myDynamicMessages DynamicMessages

	requestURL := fmt.Sprintf("%s/obp/v5.1.0/management/dynamic-message-docs", obpApiHost)

	fmt.Println("requestURL : ", requestURL)

	req, erry := http.NewRequest("GET", requestURL, nil)
	if erry != nil {
		fmt.Println("Failure : ", erry)
	}

	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"DirectLogin":  {fmt.Sprintf("token=%s", token)},
	}

	before := time.Now()

	// Fetch Request
	resp, err1 := client.Do(req)

	after := time.Now()

	duration := after.Sub(before)

	if err1 != nil {
		fmt.Println("***** Failure when getting getDynamicMessageDocs: ", err1)
	}

	// Read Response Body
	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	fmt.Println("getDynamicMessageDocs response Status : ", resp.Status)

	fmt.Println(fmt.Sprintf("getDynamicMessageDocs response Status was %s, duration was %s, tryCount was %d", resp.Status, duration, tryCount))

	if resp.StatusCode != 200 {
		fmt.Println("getDynamicMessageDocs response Body: ", string(respBody))
		fmt.Println(fmt.Sprintf("tryCount was %d", tryCount))

	}

	err2 := json.Unmarshal(respBody, &myDynamicMessages)

	if err2 != nil {
		fmt.Println(err2)
	}

	for i := 0; i < len(myDynamicMessages.DynamicMessageDocs); i++ {
		fmt.Printf(myDynamicMessages.DynamicMessageDocs[i].Process)
	}

	return len(myDynamicMessages.DynamicMessageDocs), nil

}
