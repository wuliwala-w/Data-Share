

./network.sh up createChannel -c mychannel

./network.sh deployCC -ccn datashare -ccp ../chaincode/datashare/ -ccl go -ccep "OR('Org1MSP.peer','Org2MSP.peer')"

###Org1:
export PATH=${PWD}/../bin:${PWD}:$PATH
export FABRIC_CFG_PATH=$PWD/../config/
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_ADDRESS=localhost:7051

###Org2:
export PATH=${PWD}/../bin:${PWD}:$PATH
export FABRIC_CFG_PATH=$PWD/../config/
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID="Org2MSP"
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_ADDRESS=localhost:9051

###Org1:

####生成Org的公钥私钥
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"GenerateKeys","Args":[]}'

####查询Org1的公钥
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"QueryPublicKey","Args":["Org1MSP"]}'

####查询Org1的私钥
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"QueryPrivateKey","Args":[]}'


####文件私有属性描述
export FILE_PROPERTIES=$(echo -n "{\"object_type\":\"file_properties\",\"file_id\":\"file1\",\"address\":\"www.file1.com\",\"level\":1,\"salt\":\"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\"}" | base64 | tr -d \\n)

####创建文件
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"CreateFile","Args":["file1", "A new file for Org1MSP"]}' --transient "{\"file_properties\":\"$FILE_PROPERTIES\"}"

####查询文件相应的签名证书
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"ReadCertificate","Args":["file1","Org1MSP"]}'


####查询文件私有属性
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"GetFilePrivateProperties","Args":["file1"]}'

####查询链上共有文件属性
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"ReadFileWithOrg","Args":["file1","Org1MSP"]}'

####更改文件分享描述
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"ChangePublicDescription","Args":["file1","This file can not be shared"]}'

####再次查询文件描述
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"ReadFileWithOrg","Args":["file1","Org1MSP"]}'

###Org2:

####验证证书签名
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"VerifyCertificate","Args":["file1","Org1MSP"]}'

####查询文件描述
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"ReadFileWithOrg","Args":["file1","Org1MSP"]}'

####恶意更改文件描述，会发现无法更改
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"ChangePublicDescription","Args":["file1","this file cannot be used"]}'

###以Org1的身份同意共享:
####添加安全词和共享id
export FILE_SWORD=$(echo -n "{\"file_id\":\"file1\",\"trans_id\":\"109f4b3c50d7b0df729d299bc6f8e9ef9066971f\",\"sword\":\"apple\"}" | base64 | tr -d \\n)
####同意共享:
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"AgreeToShare","Args":["file1"]}' --transient "{\"file_sword\":\"$FILE_SWORD\"}"

####读取约定安全词
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"GetFileShareSword","Args":["file1"]}'

###以Org2的身份获取文件:
####与Org1链下沟通获取并添加文件属性描述
export FILE_PROPERTIES=$(echo -n "{\"object_type\":\"file_properties\",\"file_id\":\"file1\",\"address\":\"www.file1.com\",\"level\":1,\"salt\":\"a94a8fe5ccb19ba61c4c0873d391e987982fbbd3\"}" | base64 | tr -d \\n)
####验证文件属性,得到true说明验证成功
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"VerifyFileProperties","Args":["file1","Org1MSP"]}' --transient "{\"file_properties\":\"$FILE_PROPERTIES\"}"

####添加共享id和安全词
export FILE_SWORD=$(echo -n "{\"file_id\":\"file1\",\"trans_id\":\"109f4b3c50d7b0df729d299bc6f8e9ef9066971f\",\"sword\":\"apple\"}" | base64 | tr -d \\n)
####同意接收文件
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"AgreeToRequest","Args":["file1"]}' --transient "{\"file_sword\":\"$FILE_SWORD\"}"

###以Org1身份文件共享:
####共享文件
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"TransferFile","Args":["file1","Org2MSP"]}' --transient "{\"file_properties\":\"$FILE_PROPERTIES\",\"file_sword\":\"$FILE_SWORD\"}" --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt" --peerAddresses localhost:9051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"

####查询是否共享成功
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"ReadFileWithOrg","Args":["file1","Org2MSP"]}'

####查询拥有file1的所有组织
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"ReadFile","Args":["file1"]}'

####查询file1的转移历史记录
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"QueryHistoryRecord","Args":["file1"]}'


###以Org2身份更改文件属性描述:
####读取文件私有属性
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"GetFilePrivateProperties","Args":["file1"]}'

####更新链上描述
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"ChangePublicDescription","Args":["file1","This file is for shared"]}'

####再次查询
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"ReadFile","Args":["file1"]}'

####查询文件历史数据
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n datashare -c '{"function":"QueryFileHistory","Args":["file1"]}'

"file+history"作为key，share，recieve，time，
