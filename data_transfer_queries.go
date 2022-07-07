/*
 SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// QueryResult structure used for handling result of query
type QueryResult struct {
	Record    *File
	TxId      string    `json:"txId"`
	Timestamp time.Time `json:"timestamp"`
}

type QueryFileResult struct {
	Record *File
}

type TransRecord struct {
	ID        string `json:"file_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Timestamp string `json:"timestamp"`
}

type Agreement struct {
	ID      string `json:"file_id"`
	Sword   string `json:"sword"`
	TransID string `json:"trans_id"`
}

func (s *SmartContract) ReadCertificate(ctx contractapi.TransactionContextInterface, fileID string, createrOrg string) (*Certificate, error) {
	index := "certificate"
	cfc, err := ctx.GetStub().CreateCompositeKey(index, []string{fileID, createrOrg})
	if err != nil {
		return nil, fmt.Errorf("failed to create composite key: %v", err)
	}
	certificateJSON, err := ctx.GetStub().GetState(cfc)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if certificateJSON == nil {
		return nil, fmt.Errorf("%s does not exist", fileID)
	}

	var certificate *Certificate
	err = json.Unmarshal(certificateJSON, &certificate)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}
func (s *SmartContract) QueryPrivateKey(ctx contractapi.TransactionContextInterface) (string, error) {

	clientOrgID, err := getClientOrgID(ctx, true)
	if err != nil {
		return "", fmt.Errorf("failed to get verified OrgID: %v", err)
	}
	collection, err := getClientImplicitCollectionName(ctx)
	if err != nil {
		return "", err
	}
	privateBytes, err := ctx.GetStub().GetPrivateData(collection, clientOrgID)
	if err != nil {
		return "", fmt.Errorf("failed to read file private properties from client org's collection: %v", err)
	}
	if privateBytes == nil {
		return "", fmt.Errorf("file private details does not exist in client org's collection: %s", clientOrgID)
	}
	return string(privateBytes), nil
}

func (s *SmartContract) QueryPublicKey(ctx contractapi.TransactionContextInterface, OrgID string) (string, error) {

	publicKey, err := ctx.GetStub().GetState(OrgID)
	if err != nil {
		return "", fmt.Errorf("failed to read from world state: %v", err)
	}
	if publicKey == nil {
		return "", fmt.Errorf("%s's public key does not exist", OrgID)
	}
	return string(publicKey), nil
}

// ReadAsset returns the public asset data
func (s *SmartContract) ReadFile(ctx contractapi.TransactionContextInterface, fileID string) ([]File, error) {
	// Since only public data is accessed in this function, no access control is required
	index := "id-org"

	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(index, []string{fileID})

	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	//results := []QueryFileResult{}
	var files []File

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()

		if err != nil {
			return nil, err
		}

		var file File
		_ = json.Unmarshal(queryResponse.Value, &file)

		//queryFileResult := QueryFileResult{Record: file}
		fmt.Println("fileID:%s,fileOrg:%s", file.ID, file.OwnerOrg)
		if file.ID == fileID {
			files = append(files, file)
		}
	}

	return files, nil
}

func (s *SmartContract) ReadFileWithOrg(ctx contractapi.TransactionContextInterface, fileID string, OwnerOrg string) (*File, error) {
	// Since only public data is accessed in this function, no access control is required
	index := "id-org"
	ino, err := ctx.GetStub().CreateCompositeKey(index, []string{fileID, OwnerOrg})
	if err != nil {
		return nil, fmt.Errorf("failed to create composite key: %v", err)
	}
	fileJSON, err := ctx.GetStub().GetState(ino)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if fileJSON == nil {
		return nil, fmt.Errorf("%s does not exist", fileID)
	}

	var file *File
	err = json.Unmarshal(fileJSON, &file)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// GetFilePrivateProperties returns the immutable file properties from owner's private data collection
func (s *SmartContract) GetFilePrivateProperties(ctx contractapi.TransactionContextInterface, fileID string) (string, error) {
	// In this scenario, client is only authorized to read/write private data from its own peer.
	collection, err := getClientImplicitCollectionName(ctx)
	if err != nil {
		return "", err
	}

	immutableProperties, err := ctx.GetStub().GetPrivateData(collection, fileID)
	if err != nil {
		return "", fmt.Errorf("failed to read file private properties from client org's collection: %v", err)
	}
	if immutableProperties == nil {
		return "", fmt.Errorf("file private details does not exist in client org's collection: %s", fileID)
	}

	return string(immutableProperties), nil
}

// GetFileShareSword returns the share sword
func (s *SmartContract) GetFileShareSword(ctx contractapi.TransactionContextInterface, fileID string) (string, error) {
	return getFileSword(ctx, fileID, typeFileForShare)
}

// GetAssetRequestSword returns the request word
func (s *SmartContract) GetFileRequestSword(ctx contractapi.TransactionContextInterface, fileID string) (string, error) {
	return getFileSword(ctx, fileID, typeFileRequest)
}

// getFileSword gets the request sword from caller's implicit private data collection
func getFileSword(ctx contractapi.TransactionContextInterface, fileID string, swordType string) (string, error) {
	collection, err := getClientImplicitCollectionName(ctx)
	if err != nil {
		return "", err
	}

	fileSwordKey, err := ctx.GetStub().CreateCompositeKey(swordType, []string{fileID})
	if err != nil {
		return "", fmt.Errorf("failed to create composite key: %v", err)
	}

	sword, err := ctx.GetStub().GetPrivateData(collection, fileSwordKey)
	if err != nil {
		return "", fmt.Errorf("failed to read file file from implicit private data collection: %v", err)
	}
	if sword == nil {
		return "", fmt.Errorf("file sword does not exist: %s", fileID)
	}

	return string(sword), nil
}

// QueryFileShareAgreements returns all of an organization's proposed sword
func (s *SmartContract) QueryFileShareAgreements(ctx contractapi.TransactionContextInterface) ([]Agreement, error) {
	return queryAgreementsByType(ctx, typeFileForShare)
}

// QueryFileRequestAgreements returns all of an organization's proposed sword
func (s *SmartContract) QueryFileRequestAgreements(ctx contractapi.TransactionContextInterface) ([]Agreement, error) {
	return queryAgreementsByType(ctx, typeFileRequest)
}

func queryAgreementsByType(ctx contractapi.TransactionContextInterface, agreeType string) ([]Agreement, error) {
	collection, err := getClientImplicitCollectionName(ctx)
	if err != nil {
		return nil, err
	}

	// Query for any object type starting with `agreeType`
	agreementsIterator, err := ctx.GetStub().GetPrivateDataByPartialCompositeKey(collection, agreeType, []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to read from private data collection: %v", err)
	}
	defer agreementsIterator.Close()

	var agreements []Agreement
	for agreementsIterator.HasNext() {
		resp, err := agreementsIterator.Next()
		if err != nil {
			return nil, err
		}

		var agreement Agreement
		err = json.Unmarshal(resp.Value, &agreement)
		if err != nil {
			return nil, err
		}

		agreements = append(agreements, agreement)
	}

	return agreements, nil
}

// QueryAssetHistory returns the chain of custody for a file since issuance
// func (s *SmartContract) QueryFileHistory(ctx contractapi.TransactionContextInterface, fileID string) ([]QueryResult, error) {
// 	resultsIterator, err := ctx.GetStub().GetHistoryForKey(fileID)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resultsIterator.Close()

// 	var results []QueryResult
// 	for resultsIterator.HasNext() {
// 		response, err := resultsIterator.Next()
// 		if err != nil {
// 			return nil, err
// 		}

// 		var file *File
// 		err = json.Unmarshal(response.Value, &file)
// 		if err != nil {
// 			return nil, err
// 		}

// 		timestamp, err := ptypes.Timestamp(response.Timestamp)
// 		if err != nil {
// 			return nil, err
// 		}
// 		record := QueryResult{
// 			TxId:      response.TxId,
// 			Timestamp: timestamp,
// 			Record:    file,
// 		}
// 		results = append(results, record)
// 	}

// 	return results, nil
// }

func (s *SmartContract) QueryHistoryRecord(ctx contractapi.TransactionContextInterface, fileID string) ([]TransRecord, error) {
	// Since only public data is accessed in this function, no access control is required
	index := "id-time"

	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(index, []string{fileID})

	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var records []TransRecord

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()

		if err != nil {
			return nil, err
		}

		var record TransRecord
		_ = json.Unmarshal(queryResponse.Value, &record)

		fmt.Println("fileID:%s,fileOrg:%s", record.ID, record.Timestamp)
		if record.ID == fileID {
			records = append(records, record)
		}
	}

	return records, nil
}
