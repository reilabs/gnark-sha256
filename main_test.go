package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCircuit(t *testing.T) {
	var circuit Circuit

	assignment := Circuit{
		Iters:  1,
		H:      [8]frontend.Variable{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
		Input:  [16]frontend.Variable{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		Output: [8]frontend.Variable{3592665057, 2164530888, 1223339564, 3041196771, 2006723467, 2963045520, 3851824201, 3453903005},
	}
	err := test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.Nil(t, err)
}
