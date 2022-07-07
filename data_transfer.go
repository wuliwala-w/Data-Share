/*
 SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hyperledger/fabric-chaincode-go/pkg/statebased"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	typeFileForShare       = "S"
	typeFileRequest        = "R"
	typeFileShareReceipt   = "SR"
	typeFIleRequestReceipt = "RR"
)

type SmartContract struct {
	contractapi.Contract
}

// File struct and properties must be exported (start with capitals) to work with contract api metadata
type File struct {
	ObjectType        string `json:"objectType"` // ObjectType is used to distinguish different object types in the same chaincode namespace
	ID                string `json:"fileID"`
	OwnerOrg          string `json:"ownerOrg"`
	CreaterOrg        string `json:"createrOrg"`
	PublicDescription string `json:"publicDescription"`
}

type Certificate struct {
	ObjectType string `json:"objectType"`
	ID         string `json:"fileID"`
	CreaterOrg string `json:"createrOrg"`
	Timestamp  string `json:"timestamp"`
	Signature  string `json:"signature"`
}

type receipt struct {
	sword     string
	timestamp time.Time
}

//generate public key and private key
func (s *SmartContract) GenerateKeys(ctx contractapi.TransactionContextInterface) error {

	privateKey, publicKey, _ := GenerateECCKey()
	clientOrgID, err := getClientOrgID(ctx, true)
	if err != nil {
		return fmt.Errorf("failed to get verified OrgID: %v", err)
	}

	err = ctx.GetStub().PutState(clientOrgID, publicKey)
	if err != nil {
		return fmt.Errorf("failed to put file in public data: %v", err)
	}

	collection := buildCollectionName(clientOrgID)
	err = ctx.GetStub().PutPrivateData(collection, clientOrgID, privateKey)
	if err != nil {
		return fmt.Errorf("failed to put File private details: %v", err)
	}

	return nil
}

func (s *SmartContract) VerifyCertificate(ctx contractapi.TransactionContextInterface, fileID, createrOrgID string) (bool, error) {
	certificate, err := s.ReadCertificate(ctx, fileID, createrOrgID)
	if err != nil {
		return false, fmt.Errorf("certificate not found!")
	}
	signatureString := certificate.ID + "||" + certificate.CreaterOrg + "||" + certificate.Timestamp
	publicKey, err := s.QueryPublicKey(ctx, createrOrgID)
	verify := VerifySignECC([]byte(signatureString), certificate.Signature, []byte(publicKey))
	return verify, nil
}

// CreateFile creates an file and sets it as owned by the client's org
func (s *SmartContract) CreateFile(ctx contractapi.TransactionContextInterface, fileID, publicDescription string) error {
	privateKey, err := s.QueryPrivateKey(ctx)
	if err != nil {
		return fmt.Errorf("private key not found!")
	}
	transientMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	// File properties must be retrieved from the transient field as they are private
	immutablePropertiesJSON, ok := transientMap["file_properties"]
	if !ok {
		return fmt.Errorf("file_properties key not found in the transient map")
	}

	// Get client org id and verify it matches peer org id.
	// In this scenario, client is only authorized to read/write private data from its own peer.
	clientOrgID, err := getClientOrgID(ctx, true)
	if err != nil {
		return fmt.Errorf("failed to get verified OrgID: %v", err)
	}

	file := File{
		ObjectType:        "file",
		ID:                fileID,
		OwnerOrg:          clientOrgID,
		CreaterOrg:        clientOrgID,
		PublicDescription: publicDescription,
	}
	fileBytes, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("failed to create file JSON: %v", err)
	}

	index := "id-org"
	ino, err := ctx.GetStub().CreateCompositeKey(index, []string{file.ID, file.OwnerOrg})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}
	err = ctx.GetStub().PutState(ino, fileBytes)
	if err != nil {
		return fmt.Errorf("failed to put file in public data: %v", err)
	}

	// Set the endorsement policy such that an owner org peer is required to endorse future updates
	err = setFileStateBasedEndorsement(ctx, file.ID, clientOrgID)
	if err != nil {
		return fmt.Errorf("failed setting state based endorsement for owner: %v", err)
	}

	// Persist private immutable file properties to owner's private data collection
	collection := buildCollectionName(clientOrgID)
	err = ctx.GetStub().PutPrivateData(collection, file.ID, immutablePropertiesJSON)
	if err != nil {
		return fmt.Errorf("failed to put File private details: %v", err)
	}

	// build certificate for new file
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to create timestamp for record: %v", err)
	}

	timestamp, err := ptypes.Timestamp(txTimestamp)
	if err != nil {
		return fmt.Errorf("failed to create timestamp for record: %v", err)
	}
	signatureString := file.ID + "||" + file.CreaterOrg + "||" + timestamp.String()
	signature, err := SignECC([]byte(signatureString), []byte(privateKey))
	if err != nil {
		return fmt.Errorf("sign error!")
	}
	certificate := Certificate{
		ObjectType: "certificate",
		ID:         file.ID,
		CreaterOrg: file.CreaterOrg,
		Timestamp:  timestamp.String(),
		Signature:  signature,
	}
	certificateBytes, err := json.Marshal(certificate)
	if err != nil {
		return fmt.Errorf("failed to create file JSON: %v", err)
	}

	index = "certificate"
	cfc, err := ctx.GetStub().CreateCompositeKey(index, []string{certificate.ID, certificate.CreaterOrg})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}
	err = ctx.GetStub().PutState(cfc, certificateBytes)
	if err != nil {
		return fmt.Errorf("failed to put file in public data: %v", err)
	}

	return nil
}

// ChangePublicDescription updates the files public description. Only the current owner can update the public description
func (s *SmartContract) ChangePublicDescription(ctx contractapi.TransactionContextInterface, fileID string, newDescription string) error {
	// No need to check client org id matches peer org id, rely on the file ownership check instead.
	clientOrgID, err := getClientOrgID(ctx, false)
	if err != nil {
		return fmt.Errorf("failed to get verified OrgID: %v", err)
	}

	file, err := s.ReadFileWithOrg(ctx, fileID, clientOrgID)
	if err != nil {
		return fmt.Errorf("failed to get file: %v", err)
	}
	fmt.Println("01filedescription:%s\n", file.PublicDescription)
	// Auth check to ensure that client's org actually owns the file
	if clientOrgID != file.OwnerOrg {
		return fmt.Errorf("a client from %s cannot update the description of a file owned by %s", clientOrgID, file.OwnerOrg)
	}

	file.PublicDescription = newDescription
	fmt.Println("02filedescription:%s\n", file.PublicDescription)
	updatedAssetJSON, err := json.Marshal(file)
	if err != nil {
		return fmt.Errorf("failed to marshal file: %v", err)
	}
	index := "id-org"
	ino, err := ctx.GetStub().CreateCompositeKey(index, []string{fileID, clientOrgID})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}
	return ctx.GetStub().PutState(ino, updatedAssetJSON)
}

// AgreeToShare adds share party's asking sword to share party's implicit private data collection
func (s *SmartContract) AgreeToShare(ctx contractapi.TransactionContextInterface, fileID string) error {

	clientOrgID, err := getClientOrgID(ctx, true)
	if err != nil {
		return fmt.Errorf("failed to get verified OrgID: %v", err)
	}
	file, err := s.ReadFileWithOrg(ctx, fileID, clientOrgID)
	if err != nil {
		return err
	}

	// Verify that this clientOrgId actually owns the asset.
	if clientOrgID != file.OwnerOrg {
		return fmt.Errorf("a client from %s cannot sell an asset owned by %s", clientOrgID, file.OwnerOrg)
	}

	return agreeToSafeWord(ctx, fileID, typeFileForShare)
}

// AgreeToRequest adds requesting party's safe word to requesting party's implicit private data collection
func (s *SmartContract) AgreeToRequest(ctx contractapi.TransactionContextInterface, fileID string) error {
	return agreeToSafeWord(ctx, fileID, typeFileRequest)
}

// agreeToSafeWord adds a safe word to caller's implicit private data collection
func agreeToSafeWord(ctx contractapi.TransactionContextInterface, fileID string, swordType string) error {
	// In this scenario, client is only authorized to read/write private data from its own peer.
	clientOrgID, err := getClientOrgID(ctx, true)
	if err != nil {
		return fmt.Errorf("failed to get verified OrgID: %v", err)
	}

	transMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	// safe word must be retrieved from the transient field as they are private
	sword, ok := transMap["file_sword"]
	if !ok {
		return fmt.Errorf("file_sword key not found in the transient map")
	}

	collection := buildCollectionName(clientOrgID)

	// Persist the agreed to price in a collection sub-namespace based on swordType key prefix,
	// to avoid collisions between private asset properties, share sword, and request sword
	fileSwordKey, err := ctx.GetStub().CreateCompositeKey(swordType, []string{fileID})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}

	// The Sword hash will be verified later, therefore always pass and persist price bytes as is,
	// so that there is no risk of nondeterministic marshaling.
	err = ctx.GetStub().PutPrivateData(collection, fileSwordKey, sword)
	if err != nil {
		return fmt.Errorf("failed to put asset bid: %v", err)
	}

	return nil
}

// VerifyFileProperties Allows a request party to validate the properties of
// an file against the owner's implicit private data collection
func (s *SmartContract) VerifyFileProperties(ctx contractapi.TransactionContextInterface, fileID string, OwnerOrg string) (bool, error) {
	transMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return false, fmt.Errorf("error getting transient: %v", err)
	}

	/// Asset properties must be retrieved from the transient field as they are private
	immutablePropertiesJSON, ok := transMap["file_properties"]
	if !ok {
		return false, fmt.Errorf("file_properties key not found in the transient map")
	}

	file, err := s.ReadFileWithOrg(ctx, fileID, OwnerOrg)
	if err != nil {
		return false, fmt.Errorf("failed to get file: %v", err)
	}

	collectionOwner := buildCollectionName(file.OwnerOrg)
	immutablePropertiesOnChainHash, err := ctx.GetStub().GetPrivateDataHash(collectionOwner, fileID)
	if err != nil {
		return false, fmt.Errorf("failed to read file private properties hash from sharer's collection: %v", err)
	}
	if immutablePropertiesOnChainHash == nil {
		return false, fmt.Errorf("file private properties hash does not exist: %s", fileID)
	}

	hash := sha256.New()
	hash.Write(immutablePropertiesJSON)
	calculatedPropertiesHash := hash.Sum(nil)

	// verify that the hash of the passed immutable properties matches the on-chain hash
	if !bytes.Equal(immutablePropertiesOnChainHash, calculatedPropertiesHash) {
		return false, fmt.Errorf("hash %x for passed immutable properties %s does not match on-chain hash %x",
			calculatedPropertiesHash,
			immutablePropertiesJSON,
			immutablePropertiesOnChainHash,
		)
	}

	return true, nil
}

// TransferFile checks transfer conditions and then transfers file state to request party.
// TransferFile can only be called by current owner
func (s *SmartContract) TransferFile(ctx contractapi.TransactionContextInterface, fileID string, requestOrgID string) error {
	clientOrgID, err := getClientOrgID(ctx, false)
	if err != nil {
		return fmt.Errorf("failed to get verified OrgID: %v", err)
	}

	transMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("error getting transient data: %v", err)
	}

	immutablePropertiesJSON, ok := transMap["file_properties"]
	if !ok {
		return fmt.Errorf("file_properties key not found in the transient map")
	}

	swordJSON, ok := transMap["file_sword"]
	if !ok {
		return fmt.Errorf("file_sword key not found in the transient map")
	}

	var agreement Agreement //*
	err = json.Unmarshal(swordJSON, &agreement)
	if err != nil {
		return fmt.Errorf("failed to unmarshal sword JSON: %v", err)
	}

	file, err := s.ReadFileWithOrg(ctx, fileID, clientOrgID)
	if err != nil {
		return fmt.Errorf("failed to get file: %v", err)
	}

	err = verifyTransferConditions(ctx, file, immutablePropertiesJSON, clientOrgID, requestOrgID, swordJSON)
	if err != nil {
		return fmt.Errorf("failed transfer verification: %v", err)
	}

	err = transferFileState(ctx, file, immutablePropertiesJSON, clientOrgID, requestOrgID, agreement.Sword)
	if err != nil {
		return fmt.Errorf("failed asset transfer: %v", err)
	}

	return nil

}

// verifyTransferConditions checks that client org currently owns asset and that both parties have agreed on price
func verifyTransferConditions(ctx contractapi.TransactionContextInterface,
	file *File,
	immutablePropertiesJSON []byte,
	clientOrgID string,
	requestOrgID string,
	swordJSON []byte) error {

	// CHECK1: Auth check to ensure that client's org actually owns the asset

	if clientOrgID != file.OwnerOrg {
		return fmt.Errorf("a client from %s cannot transfer a asset owned by %s", clientOrgID, file.OwnerOrg)
	}

	// CHECK2: Verify that the hash of the passed immutable properties matches the on-chain hash

	collectionSeller := buildCollectionName(clientOrgID)
	immutablePropertiesOnChainHash, err := ctx.GetStub().GetPrivateDataHash(collectionSeller, file.ID)
	if err != nil {
		return fmt.Errorf("failed to read asset private properties hash from seller's collection: %v", err)
	}
	if immutablePropertiesOnChainHash == nil {
		return fmt.Errorf("asset private properties hash does not exist: %s", file.ID)
	}

	hash := sha256.New()
	hash.Write(immutablePropertiesJSON)
	calculatedPropertiesHash := hash.Sum(nil)

	// verify that the hash of the passed immutable properties matches the on-chain hash
	if !bytes.Equal(immutablePropertiesOnChainHash, calculatedPropertiesHash) {
		return fmt.Errorf("hash %x for passed immutable properties %s does not match on-chain hash %x",
			calculatedPropertiesHash,
			immutablePropertiesJSON,
			immutablePropertiesOnChainHash,
		)
	}

	// CHECK3: Verify that share and request party agreed on the same sword

	// Get share party asking sword
	fileForShareKey, err := ctx.GetStub().CreateCompositeKey(typeFileForShare, []string{file.ID})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}
	sharerSwordHash, err := ctx.GetStub().GetPrivateDataHash(collectionSeller, fileForShareKey)
	if err != nil {
		return fmt.Errorf("failed to get seller price hash: %v", err)
	}
	if sharerSwordHash == nil {
		return fmt.Errorf("seller price for %s does not exist", file.ID)
	}

	// Get request party request sword
	collectionRequester := buildCollectionName(requestOrgID)
	fileRequestKey, err := ctx.GetStub().CreateCompositeKey(typeFileRequest, []string{file.ID})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}
	requestSwordHash, err := ctx.GetStub().GetPrivateDataHash(collectionRequester, fileRequestKey)
	if err != nil {
		return fmt.Errorf("failed to get request sword hash: %v", err)
	}
	if requestSwordHash == nil {
		return fmt.Errorf("request sword for %s does not exist", file.ID)
	}

	hash = sha256.New()
	hash.Write(swordJSON)
	calculatedPriceHash := hash.Sum(nil)

	// Verify that the hash of the passed price matches the on-chain sellers price hash
	if !bytes.Equal(calculatedPriceHash, sharerSwordHash) {
		return fmt.Errorf("hash %x for passed price JSON %s does not match on-chain hash %x, seller hasn't agreed to the passed trade id and price",
			calculatedPriceHash,
			swordJSON,
			sharerSwordHash,
		)
	}

	// Verify that the hash of the passed price matches the on-chain buyer price hash
	if !bytes.Equal(calculatedPriceHash, requestSwordHash) {
		return fmt.Errorf("hash %x for passed sword JSON %s does not match on-chain hash %x, request part hasn't agreed to the passed trade id and price",
			calculatedPriceHash,
			swordJSON,
			requestSwordHash,
		)
	}

	return nil
}

// transferFileState performs the public and private state updates for the transferred asset
func transferFileState(ctx contractapi.TransactionContextInterface, file *File, immutablePropertiesJSON []byte, clientOrgID string, requestOrgID string, sword string) error {
	//file.OwnerOrg = requestOrgID
	// //updatedFile, err := json.Marshal(file)
	// if err != nil {
	// 	return err
	// }
	nfile := File{
		ObjectType:        "file",
		ID:                file.ID,
		OwnerOrg:          requestOrgID,
		CreaterOrg:        file.CreaterOrg,
		PublicDescription: file.PublicDescription,
	}
	fileBytes, err := json.Marshal(nfile)
	if err != nil {
		return fmt.Errorf("failed to create file JSON: %v", err)
	}

	index := "id-org"
	ino, err := ctx.GetStub().CreateCompositeKey(index, []string{nfile.ID, nfile.OwnerOrg})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}
	err = ctx.GetStub().PutState(ino, fileBytes)
	if err != nil {
		return fmt.Errorf("failed to put file in public data: %v", err)
	}

	// Change the endorsement policy to the new owner
	err = setFileStateBasedEndorsement(ctx, file.ID, requestOrgID)
	if err != nil {
		return fmt.Errorf("failed setting state based endorsement for new owner: %v", err)
	}

	// Transfer the private properties (delete from share party collection, create in request party collection)
	collectionSharer := buildCollectionName(clientOrgID)
	//err = ctx.GetStub().DelPrivateData(collectionSharer, file.ID)
	// if err != nil {
	// 	return fmt.Errorf("failed to delete Asset private details from seller: %v", err)
	// }

	collectionRequester := buildCollectionName(requestOrgID)
	err = ctx.GetStub().PutPrivateData(collectionRequester, file.ID, immutablePropertiesJSON)
	if err != nil {
		return fmt.Errorf("failed to put Asset private properties for buyer: %v", err)
	}

	// Delete the sword record for share party
	fileSwordKey, err := ctx.GetStub().CreateCompositeKey(typeFileForShare, []string{file.ID})
	if err != nil {
		return fmt.Errorf("failed to create composite key for sharer: %v", err)
	}

	err = ctx.GetStub().DelPrivateData(collectionSharer, fileSwordKey)
	if err != nil {
		return fmt.Errorf("failed to delete file sword from implicit private data collection for sharer: %v", err)
	}

	// Delete the sword records for request party
	fileSwordKey, err = ctx.GetStub().CreateCompositeKey(typeFileRequest, []string{file.ID})
	if err != nil {
		return fmt.Errorf("failed to create composite key for request party: %v", err)
	}

	err = ctx.GetStub().DelPrivateData(collectionRequester, fileSwordKey)
	if err != nil {
		return fmt.Errorf("failed to delete file sword from implicit private data collection for request party: %v", err)
	}

	//transfer record
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to create timestamp for record: %v", err)
	}

	timestamp, err := ptypes.Timestamp(txTimestamp)
	if err != nil {
		return err
	}
	transrecord := TransRecord{
		ID:        file.ID,
		From:      clientOrgID,
		To:        requestOrgID,
		Timestamp: timestamp.String(),
	}
	recordBytes, err := json.Marshal(transrecord)
	if err != nil {
		return fmt.Errorf("failed to create record JSON: %v", err)
	}
	index = "id-time"
	inti, err := ctx.GetStub().CreateCompositeKey(index, []string{transrecord.ID, transrecord.Timestamp})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}
	err = ctx.GetStub().PutState(inti, recordBytes)
	if err != nil {
		return fmt.Errorf("failed to put record in public data: %v", err)
	}

	// Keep record for a 'receipt' in both request and share private data collection to record the share sword and date.
	// Persist the agreed to sword in a collection sub-namespace based on receipt key prefix.
	receiptRequestKey, err := ctx.GetStub().CreateCompositeKey(typeFIleRequestReceipt, []string{file.ID, ctx.GetStub().GetTxID()})
	if err != nil {
		return fmt.Errorf("failed to create composite key for receipt: %v", err)
	}

	txTimestamp, err = ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return fmt.Errorf("failed to create timestamp for receipt: %v", err)
	}

	timestamp, err = ptypes.Timestamp(txTimestamp)
	if err != nil {
		return err
	}
	fileReceipt := receipt{
		sword:     sword,
		timestamp: timestamp,
	}
	receipt, err := json.Marshal(fileReceipt)
	if err != nil {
		return fmt.Errorf("failed to marshal receipt: %v", err)
	}

	err = ctx.GetStub().PutPrivateData(collectionRequester, receiptRequestKey, receipt)
	if err != nil {
		return fmt.Errorf("failed to put private file receipt for request party: %v", err)
	}

	receiptShareKey, err := ctx.GetStub().CreateCompositeKey(typeFileShareReceipt, []string{ctx.GetStub().GetTxID(), file.ID})
	if err != nil {
		return fmt.Errorf("failed to create composite key for receipt: %v", err)
	}

	err = ctx.GetStub().PutPrivateData(collectionSharer, receiptShareKey, receipt)
	if err != nil {
		return fmt.Errorf("failed to put private file receipt for share party: %v", err)
	}

	return nil
}

// getClientOrgID gets the client org ID.
// The client org ID can optionally be verified against the peer org ID, to ensure that a client
// from another org doesn't attempt to read or write private data from this peer.
// The only exception in this scenario is for TransferAsset, since the current owner
// needs to get an endorsement from the requester's peer.
func getClientOrgID(ctx contractapi.TransactionContextInterface, verifyOrg bool) (string, error) {
	clientOrgID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("failed getting client's orgID: %v", err)
	}

	if verifyOrg {
		err = verifyClientOrgMatchesPeerOrg(clientOrgID)
		if err != nil {
			return "", err
		}
	}

	return clientOrgID, nil
}

// verifyClientOrgMatchesPeerOrg checks the client org id matches the peer org id.
func verifyClientOrgMatchesPeerOrg(clientOrgID string) error {
	peerOrgID, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed getting peer's orgID: %v", err)
	}

	if clientOrgID != peerOrgID {
		return fmt.Errorf("client from org %s is not authorized to read or write private data from an org %s peer",
			clientOrgID,
			peerOrgID,
		)
	}

	return nil
}

// setAssetStateBasedEndorsement adds an endorsement policy to a file so that only a peer from an owning org
// can update or transfer the asset.
func setFileStateBasedEndorsement(ctx contractapi.TransactionContextInterface, fileID string, orgToEndorse string) error {
	endorsementPolicy, err := statebased.NewStateEP(nil)
	if err != nil {
		return err
	}
	err = endorsementPolicy.AddOrgs(statebased.RoleTypePeer, orgToEndorse)
	if err != nil {
		return fmt.Errorf("failed to add org to endorsement policy: %v", err)
	}
	policy, err := endorsementPolicy.Policy()
	if err != nil {
		return fmt.Errorf("failed to create endorsement policy bytes from org: %v", err)
	}
	err = ctx.GetStub().SetStateValidationParameter(fileID, policy)
	if err != nil {
		return fmt.Errorf("failed to set validation parameter on file: %v", err)
	}

	return nil
}

func buildCollectionName(clientOrgID string) string {
	return fmt.Sprintf("_implicit_org_%s", clientOrgID)
}

func getClientImplicitCollectionName(ctx contractapi.TransactionContextInterface) (string, error) {
	clientOrgID, err := getClientOrgID(ctx, true)
	if err != nil {
		return "", fmt.Errorf("failed to get verified OrgID: %v", err)
	}

	err = verifyClientOrgMatchesPeerOrg(clientOrgID)
	if err != nil {
		return "", err
	}

	return buildCollectionName(clientOrgID), nil
}

func GenerateECCKey() ([]byte, []byte, error) {
	//生成密钥对
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	//保存私钥
	eccPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create public key error")
	}
	//保存公钥
	publicKey := privateKey.PublicKey
	eccPublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create public key error")
	}
	return eccPrivateKey, eccPublicKey, nil
}

func SignECC(msg []byte, eccprivatekey []byte) (string, error) {
	//取得私钥
	privateKey, err := x509.ParseECPrivateKey(eccprivatekey)
	if err != nil {
		return "", fmt.Errorf("can not parse private key!")
	}
	//计算哈希值
	hash := sha256.New()
	//填入数据
	hash.Write(msg)
	bytes := hash.Sum(nil)
	//对哈希值生成数字签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, bytes)
	if err != nil {
		return "", fmt.Errorf("%x sign error!", bytes)
	}
	rtext, _ := r.MarshalText()
	stext, _ := s.MarshalText()
	return string(rtext) + "&&" + string(stext), nil
}

func VerifySignECC(msg []byte, sign string, eccpublickey []byte) bool {
	//读取公钥
	//publicKey := GetECCPublicKey(path)
	publicInterface, err := x509.ParsePKIXPublicKey(eccpublickey)
	if err != nil {
		panic(err)
	}
	publicKey := publicInterface.(*ecdsa.PublicKey)
	//计算哈希值
	hash := sha256.New()
	hash.Write(msg)
	bytes := hash.Sum(nil)
	//验证数字签名
	var r, s big.Int
	split := strings.Split(sign, "&&")
	rtext := []byte(split[0])
	stext := []byte(split[1])
	r.UnmarshalText(rtext)
	s.UnmarshalText(stext)
	verify := ecdsa.Verify(publicKey, bytes, &r, &s)
	return verify
}

func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		log.Panicf("Error create transfer asset chaincode: %v", err)
	}

	if err := chaincode.Start(); err != nil {
		log.Panicf("Error starting asset chaincode: %v", err)
	}
}
