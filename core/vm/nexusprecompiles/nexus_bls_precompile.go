package nexusprecompiles

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/Ethernal-Tech/bn256"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	domainApexBridgeEVMString = "DOMAIN_APEX_BRIDGE_EVM"
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
	return 50000
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

	var (
		publicKeysSerialized [][4]*big.Int
		bitmap               = NewBitmap(inputObj.Bitmap)
	)

	for i, x := range inputObj.PublicKeys {
		if bitmap.IsSet(uint64(i)) {
			publicKeysSerialized = append(publicKeysSerialized, x)
		}
	}

	quorumCnt := (len(inputObj.PublicKeys)*2)/3 + 1
	// ensure that the number of serialized public keys meets the required quorum count
	if len(publicKeysSerialized) < quorumCnt {
		return nil, errNexusBlsQuorumNotReached
	}

	signature, err := bn256.UnmarshalSignature(inputObj.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature - %w", errNexusBlsInvalidInput, err)
	}

	blsPubKeys := make([]*bn256.PublicKey, len(publicKeysSerialized))

	for i, pk := range publicKeysSerialized {
		blsPubKey, err := bn256.UnmarshalPublicKeyFromBigInt(pk)
		if err != nil {
			return nil, fmt.Errorf("%w: public key - %w", errNexusBlsInvalidInput, err)
		}

		blsPubKeys[i] = blsPubKey
	}

	if signature.VerifyAggregated(blsPubKeys, inputObj.Hash[:], c.domain) {
		return true32Byte, nil
	}

	return false32Byte, nil
}
