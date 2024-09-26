package nexusprecompiles

import (
	"encoding/hex"
	"math/big"
	"testing"

	bn256 "github.com/Ethernal-Tech/bn256"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

func TestNexusBlsPrecompile(t *testing.T) {
	const (
		validatorsCount = 8
	)

	encodeMulti := func(hash []byte, signature []byte, validatorsData []nexusValidatorData, bmp Bitmap) []byte {
		bytes, err := nexusBlsABI.Methods["nexus"].Outputs.Pack(
			[32]byte(hash), signature, validatorsData, new(big.Int).SetBytes(bmp),
		)
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

	validatorsData := make([]nexusValidatorData, len(validators))
	signatures := make([]*bn256.Signature, len(validators))

	for i, validator := range validators {
		signatures[i], err = validator.Sign(message, domain)
		require.NoError(t, err)

		validatorsData[i] = nexusValidatorData{
			Key: validator.PublicKey().ToBigInt(),
		}
	}

	t.Run("too many public keys", func(t *testing.T) {
		validators, err := bn256.GeneratePrivateKeys(maxPublicKeys + 1)
		require.NoError(t, err)

		validatorsData := make([]nexusValidatorData, len(validators))
		signatures := make([]*bn256.Signature, len(validators))

		for i, validator := range validators {
			signatures[i], err = validator.Sign(message, domain)
			require.NoError(t, err)

			validatorsData[i] = nexusValidatorData{
				Key: validator.PublicKey().ToBigInt(),
			}
		}

		signature, bmp := aggregateSignatures(signatures, 0, 5, 4, 3, 6, 2)
		bytes := encodeMulti(message, signature, validatorsData, bmp)

		_, err = b.Run(bytes)
		require.ErrorContains(t, err, "too many public keys")
	})

	t.Run("invalid signature size", func(t *testing.T) {
		_, bmp := aggregateSignatures(signatures, 0, 5, 4, 3, 6, 2)
		signature := make([]byte, maxSignatureSize+1)
		bytes := encodeMulti(message, signature, validatorsData, bmp)

		_, err := b.Run(bytes)
		require.ErrorContains(t, err, "invalid signature size")
	})

	t.Run("correct multi 1", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 0, 5, 4, 3, 6, 2)
		bytes := encodeMulti(message, signature, validatorsData, bmp)

		out, err := b.Run(bytes)
		require.NoError(t, err)
		require.Equal(t, true32Byte, out)
	})

	t.Run("correct multi 2", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 4, 5, 1, 7, 0, 2, 6)

		out, err := b.Run(encodeMulti(message, signature, validatorsData, bmp))
		require.NoError(t, err)
		require.Equal(t, true32Byte, out)
	})

	t.Run("correct multi 3", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 0, 1, 2, 3, 4, 7, 5, 6)

		out, err := b.Run(encodeMulti(message, signature, validatorsData, bmp))
		require.NoError(t, err)
		require.Equal(t, true32Byte, out)
	})

	t.Run("correct multi 4", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 7, 6, 5, 1, 3, 2)

		out, err := b.Run(encodeMulti(message, signature, validatorsData, bmp))
		require.NoError(t, err)
		require.Equal(t, true32Byte, out)
	})

	t.Run("wrong multi 1", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 7, 6, 5, 1, 3, 2)
		bytes := encodeMulti(append([]byte{1}, message...), signature, validatorsData, bmp)

		out, err := b.Run(bytes)
		require.NoError(t, err)
		require.Equal(t, false32Byte, out)
	})

	t.Run("wrong multi 2", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 7, 6, 5, 1, 3, 0)

		bmp.Set(uint64(2))

		out, err := b.Run(encodeMulti(message, signature, validatorsData, bmp))
		require.NoError(t, err)
		require.Equal(t, false32Byte, out)
	})

	t.Run("multi quorum not reached", func(t *testing.T) {
		signature, bmp := aggregateSignatures(signatures, 7, 6, 5, 1, 3)
		bytes := encodeMulti(message, signature, validatorsData, bmp)

		_, err := b.Run(bytes)
		require.ErrorIs(t, err, errNexusBlsQuorumNotReached)
	})

	t.Run("correct multi with data from nexus", func(t *testing.T) {
		input := "01ed70784af271d61a6e8107026a393753a934cfd3721e02e0ddc76bf9e0aac036000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000001d00000000000000000000000000000000000000000000000000000000000000400e5c559fa8d70287f2d78008f9ac39fa514bea03fe5e6dd38540cba57e799aa32ca15dbb778ca5213e4b891d9a24e7ba77ecd6d3169b6df3368760b4254c43160000000000000000000000000000000000000000000000000000000000000005245442442a035df9fd23ccf4bcd9033c1861f51c132e41240b1cb333722207b927ebda3dbf71c1b3f18322502b8ce54eb663d601ad0923c4320d342998e0dc20067f37e2108a9ce2299499751dbfa5b34a4e1bbfd45e79c2d7b8b321fe837b782bab086b8a46cfbe1d9e50c3c376626960c4220947193670be67040ed3e5b2d212976da771efe7252e97aae6202339c8e47a17e5590949d9e178d3306c9e7a0904b04488bce7b0df812ac2cba344e5c741c6b87b22e5dbf2a5999122cd8e16d01b4ce39bf0ae5c7ec89560b850117dd97df4b1a6353ca9fd4be0e7949bf54cf11ab0c4b60e17d476fc4acabd5b2885a8ff092f116cc9b5397abbb9643baf0a03238457fd37a969e77499219542f105596e0221ea44a9353b0591c2fab8774e3f16bb2d74fce60d71241366bc952f561bf27996f96c487f6dad2a2dfff5a1e8f223bc4a5c89b85227f13659347f0f0d81172c54801d490c81975557c0a4f2f8780c640351098093f27b6c7ec54ce46e8f05e3f8274d096a19e5124f47ddbfefe42d93a8a5951dd8a25b5d85bfc6a5087a4c4a74bb43549371d427199d3246a0971835ecb9928812555876789b98a5193db7c8cd0f4fe02ad51c998a88718557e1176e5d951c95e3a5f348198ce9a4683cd5f78518748df4b6896f73a4bf0df6c813e0a49f3b47329c119dada4e5572bda23cc2c8b7c0fa464ca0e85c0eae3c1cd0c693e4e06f0dfb3f7544e92e47671f0cf0b28a43052adb6ec5a06f158b313e1034b23e3bb20fd755b86d973089ad3781c41e8e323702c08a1dcbe03c48f2fd4270488dd34a524abefca463855864974a0874bc03a8ac2003d7285158780228e25b762310baae1788ddcd0c9a85f4be2f38ac0cda3dd15d2e8add98bb52b447e"

		bytes, err := hex.DecodeString(input)
		require.NoError(t, err)

		out, err := NexusBlsPrecompile.Run(bytes)
		require.NoError(t, err)
		require.Equal(t, true32Byte, out)
	})
}
