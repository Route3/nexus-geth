package nexusprecompiles

import (
	"math/big"
	"testing"

	bn256 "github.com/Ethernal-Tech/bn256"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func Test_NexusBlsPrecompile(t *testing.T) {
	const (
		validatorsCount = 8
	)

	encodeMulti := func(hash []byte, signature []byte, publicKeys [][4]*big.Int, bmp Bitmap) []byte {
		bytes, err := abi.Arguments{{Type: nexusBlsMultiABIType}}.Pack(&nexusBlsPrecompileTuple{
			Hash:       [32]byte(hash),
			Signature:  signature,
			PublicKeys: publicKeys,
			Bitmap:     new(big.Int).SetBytes(bmp),
		})
		require.NoError(t, err)

		return append([]byte{1}, bytes...)
	}

	aggregateSignatures := func(
		allSignatures []*bn256.Signature, indexes ...int,
	) ([]byte, Bitmap) {
		bmp := Bitmap{}
		signatures := make(bn256.Signatures, len(indexes))

		for i, indx := range indexes {
			signatures[i] = allSignatures[indx]
			bmp.Set(uint64(indx))
		}

		signature, err := signatures.Aggregate().Marshal()
		require.NoError(t, err)

		return signature, bmp
	}

	domain := crypto.Keccak256([]byte("sevap is in the house!"))
	message := crypto.Keccak256([]byte("test message to sign"))
	b := &nexusBlsPrecompile{
		domain: domain,
	}

	validators, err := bn256.GeneratePrivateKeys(validatorsCount)
	require.NoError(t, err)

	pubKeys := make([][4]*big.Int, len(validators))
	signatures := make([]*bn256.Signature, len(validators))

	for i, validator := range validators {
		signatures[i], err = validator.Sign(message, domain)
		require.NoError(t, err)

		pubKeys[i] = validator.PublicKey().ToBigInt()
	}

	t.Run("too many public keys", func(t *testing.T) {
		validators, err := bn256.GeneratePrivateKeys(maxPublicKeys + 1)
		require.NoError(t, err)

		pubKeys := make([][4]*big.Int, len(validators))
		signatures := make([]*bn256.Signature, len(validators))

		for i, validator := range validators {
			signatures[i], err = validator.Sign(message, domain)
			require.NoError(t, err)

			pubKeys[i] = validator.PublicKey().ToBigInt()
		}

		signature, bmp := aggregateSignatures(signatures, 0, 5, 4, 3, 6, 2)
		bytes := encodeMulti(message, signature, pubKeys, bmp)

		_, err = b.Run(bytes)
		require.ErrorContains(t, err, "too many public keys")
	})

	t.Run("invalid signature size", func(t *testing.T) {
		_, bmp := aggregateSignatures(signatures, 0, 5, 4, 3, 6, 2)
		signature := make([]byte, maxSignatureSize+1)
		bytes := encodeMulti(message, signature, pubKeys, bmp)

		_, err := b.Run(bytes)
		require.ErrorContains(t, err, "invalid signature size")
	})

	t.Run("correct multi 1", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 0, 5, 4, 3, 6, 2)
		bytes := encodeMulti(message, signature, pubKeys, bmp)

		out, err := b.Run(bytes)
		require.NoError(t, err)
		require.Equal(t, true32Byte, out)
	})

	t.Run("correct multi 2", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 4, 5, 1, 7, 0, 2, 6)

		out, err := b.Run(encodeMulti(message, signature, pubKeys, bmp))
		require.NoError(t, err)
		require.Equal(t, true32Byte, out)
	})

	t.Run("correct multi 3", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 0, 1, 2, 3, 4, 7, 5, 6)

		out, err := b.Run(encodeMulti(message, signature, pubKeys, bmp))
		require.NoError(t, err)
		require.Equal(t, true32Byte, out)
	})

	t.Run("correct multi 4", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 7, 6, 5, 1, 3, 2)

		out, err := b.Run(encodeMulti(message, signature, pubKeys, bmp))
		require.NoError(t, err)
		require.Equal(t, true32Byte, out)
	})

	t.Run("wrong multi 1", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 7, 6, 5, 1, 3, 2)
		bytes := encodeMulti(append([]byte{1}, message...), signature, pubKeys, bmp)

		out, err := b.Run(bytes)
		require.NoError(t, err)
		require.Equal(t, false32Byte, out)
	})

	t.Run("wrong multi 2", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 7, 6, 5, 1, 3, 0)

		bmp.Set(uint64(2))

		out, err := b.Run(encodeMulti(message, signature, pubKeys, bmp))
		require.NoError(t, err)
		require.Equal(t, false32Byte, out)
	})

	t.Run("multi quorum not reached", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 7, 6, 5, 1, 3)
		bytes := encodeMulti(message, signature, pubKeys, bmp)

		_, err := b.Run(bytes)
		require.ErrorIs(t, err, errNexusBlsQuorumNotReached)
	})
}
