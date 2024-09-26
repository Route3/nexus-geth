package nexusprecompiles

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	bn256 "github.com/Ethernal-Tech/bn256"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	domainApexBridgeEVMString = "DOMAIN_APEX_BRIDGE_EVM"
	maxPublicKeys             = 100
	maxSignatureSize          = 128
)

var (
	NexusBlsPrecompile = &nexusBlsPrecompile{
		domain: crypto.Keccak256([]byte(domainApexBridgeEVMString)),
	}
	NexusBLSPrecompileAddr = common.HexToAddress("0x2060")

	errNexusBlsInvalidInput     = errors.New("invalid input")
	errNexusBlsQuorumNotReached = errors.New("quorum not reached")

	true32Byte  = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	false32Byte = make([]byte, 32)

	nexusBlsABI, _ = abi.JSON(strings.NewReader(`[{
		"outputs":[
        	{"name":"hash","type":"bytes32"},
        	{"name":"signature","type":"bytes"},
        	{
				"name":"validatorsData",
				"type":"tuple[]",
				"components":[
					{"name":"key","type":"uint256[4]"}
				]
			},
        	{"name":"bitmap","type":"uint256"}
		],
    	"name":"nexus",
		"type":"function"
	}]`))
)

type nexusValidatorData struct {
	Key [4]*big.Int `abi:"key"`
}

type nexusBlsPrecompileParams struct {
	Hash           [32]byte             `abi:"hash"`
	Signature      []byte               `abi:"signature"`
	ValidatorsData []nexusValidatorData `abi:"validatorsData"`
	Bitmap         *big.Int             `abi:"bitmap"`
}

type nexusBlsPrecompile struct {
	domain []byte
}

func (c *nexusBlsPrecompile) RequiredGas(input []byte) uint64 {
	return 150_000
}

func (c *nexusBlsPrecompile) Run(input []byte) ([]byte, error) {
	if len(input) < 2 {
		return nil, errNexusBlsInvalidInput
	}

	var inputObj nexusBlsPrecompileParams

	if err := nexusBlsABI.UnpackIntoInterface(&inputObj, "nexus", input[1:]); err != nil {
		return nil, err
	}

	if len(inputObj.Signature) > maxSignatureSize {
		return nil, fmt.Errorf("%w: invalid signature size - %d", errNexusBlsInvalidInput, len(inputObj.Signature))
	}

	if len(inputObj.ValidatorsData) > maxPublicKeys {
		return nil, fmt.Errorf("%w: too many public keys - %d", errNexusBlsInvalidInput, len(inputObj.ValidatorsData))
	}

	publicKeys := make([]*bn256.PublicKey, 0, len(inputObj.ValidatorsData))
	bitmap := NewBitmap(inputObj.Bitmap)

	for i, pkSerialized := range inputObj.ValidatorsData {
		if !bitmap.IsSet(uint64(i)) {
			continue
		}

		pubKey, err := bn256.UnmarshalPublicKeyFromBigInt(pkSerialized.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: public key - %w", errNexusBlsInvalidInput, err)
		}

		publicKeys = append(publicKeys, pubKey)
	}

	quorumCnt := (len(inputObj.ValidatorsData)*2)/3 + 1
	// ensure that the number of serialized public keys meets the required quorum count
	if len(publicKeys) < quorumCnt {
		return nil, errNexusBlsQuorumNotReached
	}

	signature, err := bn256.UnmarshalSignature(inputObj.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature - %w", errNexusBlsInvalidInput, err)
	}

	if signature.VerifyAggregated(publicKeys, inputObj.Hash[:], c.domain) {
		return true32Byte, nil
	}

	return false32Byte, nil
}
