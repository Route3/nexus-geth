package nexusprecompiles

import (
	"errors"
	"fmt"
	"math/big"

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

	nexusBlsMultiABIType, _ = abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{
			Name: "hash",
			Type: "bytes32",
		},
		{
			Name: "signature",
			Type: "bytes",
		},
		{
			Name: "publicKeys",
			Type: "uint256[4][]",
		},
		{
			Name: "bitmap",
			Type: "uint256",
		},
	})

	true32Byte  = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	false32Byte = make([]byte, 32)
)

type nexusBlsPrecompileTuple struct {
	Hash       [32]byte      `json:"hash" abi:"hash"`
	Signature  []byte        `json:"signature" abi:"signature"`
	PublicKeys [][4]*big.Int `json:"publicKeys" abi:"publicKeys"`
	Bitmap     *big.Int      `json:"bitmap" abi:"bitmap"`
}

// ecrecover implemented as a native contract.
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

	dt, err := abi.Arguments{{Type: nexusBlsMultiABIType}}.Unpack(input[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: unpack error - %w", errNexusBlsInvalidInput, err)
	}

	inputObj, ok := abi.ConvertType(dt[0], new(nexusBlsPrecompileTuple)).(*nexusBlsPrecompileTuple)
	if !ok {
		return nil, errNexusBlsInvalidInput
	}

	if len(inputObj.Signature) > maxSignatureSize {
		return nil, fmt.Errorf("%w: invalid signature size - %d", errNexusBlsInvalidInput, len(inputObj.Signature))
	}

	if len(inputObj.PublicKeys) > maxPublicKeys {
		return nil, fmt.Errorf("%w: too many public keys - %d", errNexusBlsInvalidInput, len(inputObj.PublicKeys))
	}

	publicKeys := make([]*bn256.PublicKey, 0, len(inputObj.PublicKeys))
	bitmap := NewBitmap(inputObj.Bitmap)

	for i, pkSerialized := range inputObj.PublicKeys {
		if !bitmap.IsSet(uint64(i)) {
			continue
		}

		pubKey, err := bn256.UnmarshalPublicKeyFromBigInt(pkSerialized)
		if err != nil {
			return nil, fmt.Errorf("%w: public key - %w", errNexusBlsInvalidInput, err)
		}

		publicKeys = append(publicKeys, pubKey)
	}

	quorumCnt := (len(inputObj.PublicKeys)*2)/3 + 1
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
