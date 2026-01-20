package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"math/big"
)

var K = [64]uint32{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}

type Hasher struct {
	api     frontend.API
	spreads [17]logderivlookup.Table
}

func initSpread(api frontend.API, size int) logderivlookup.Table {
	table := logderivlookup.New(api)
	for i := 0; i < (1 << size); i++ {
		res := 0
		for j := 0; j < size; j++ {
			res |= (i & (1 << j)) << j
		}
		table.Insert(res)
	}
	return table
}

func NewHasher(api frontend.API) *Hasher {
	spreads := [17]logderivlookup.Table{}
	neededSizes := []int{2, 3, 4, 5, 6, 7, 9, 10, 11, 13, 14, 16}
	//neededSizes := []int{2, 3, 4, 7, 10, 11, 13, 14, 16}

	for _, size := range neededSizes {
		spreads[size] = initSpread(api, size)
	}
	return &Hasher{
		api:     api,
		spreads: spreads,
	}
}

func (hasher *Hasher) splitAndSpread4(x frontend.Variable, a, b, c, d int) (frontend.Variable, frontend.Variable, frontend.Variable, frontend.Variable) {
	r, _ := hasher.api.NewHint(func(field *big.Int, inputs []*big.Int, results []*big.Int) error {
		f := inputs[0].Int64()
		*results[0] = *big.NewInt((f & (((1 << a) - 1) << (b + c + d))) >> (b + c + d))
		*results[1] = *big.NewInt((f & (((1 << b) - 1) << (c + d))) >> (c + d))
		*results[2] = *big.NewInt((f & (((1 << c) - 1) << (d))) >> (d))
		*results[3] = *big.NewInt(f & ((1 << d) - 1))
		return nil
	}, 4, x)
	rec := hasher.api.Add(
		hasher.api.Mul(r[0], 1<<(b+c+d)),
		hasher.api.Mul(r[1], 1<<(c+d)),
		hasher.api.Mul(r[2], 1<<d),
		r[3])
	hasher.api.AssertIsEqual(x, rec)

	return hasher.spreads[a].Lookup(r[0])[0], hasher.spreads[b].Lookup(r[1])[0], hasher.spreads[c].Lookup(r[2])[0], hasher.spreads[d].Lookup(r[3])[0]
}

func (hasher *Hasher) spread(x frontend.Variable) frontend.Variable {
	r, _ := hasher.api.NewHint(func(field *big.Int, inputs []*big.Int, results []*big.Int) error {
		f := inputs[0].Int64()
		*results[0] = *big.NewInt((f & (((1 << 16) - 1) << 16)) >> 16)
		*results[1] = *big.NewInt(f & ((1 << 16) - 1))
		return nil
	}, 2, x)
	rec := hasher.api.Add(
		hasher.api.Mul(r[0], 1<<16),
		r[1],
	)
	hasher.api.AssertIsEqual(x, rec)
	hi := hasher.spreads[16].Lookup(r[0])[0]
	low := hasher.spreads[16].Lookup(r[1])[0]
	return hasher.api.Add(low, hasher.api.Mul(hi, 1<<32))
}

func (hasher *Hasher) unspread(x frontend.Variable) (odd, even frontend.Variable) {
	r, _ := hasher.api.NewHint(func(field *big.Int, inputs []*big.Int, results []*big.Int) error {
		f := inputs[0].Int64()
		e, o := int64(0), int64(0)
		for i := 0; i < 32; i++ {
			e |= ((f >> (2 * i)) & 1) << i
			o |= ((f >> (2*i + 1)) & 1) << i
		}
		*results[0] = *big.NewInt((o & 0xFFFF0000) >> 16)
		*results[1] = *big.NewInt(o & 0x0000FFFF)
		*results[2] = *big.NewInt((e & 0xFFFF0000) >> 16)
		*results[3] = *big.NewInt(e & 0x0000FFFF)
		return nil
	}, 4, x)
	hiOdd, lowOdd, hiEven, lowEven := r[0], r[1], r[2], r[3]
	hiOddS := hasher.spreads[16].Lookup(hiOdd)[0]
	lowOddS := hasher.spreads[16].Lookup(lowOdd)[0]
	hiEvenS := hasher.spreads[16].Lookup(hiEven)[0]
	lowEvenS := hasher.spreads[16].Lookup(lowEven)[0]
	rec := hasher.api.Add(
		lowEvenS,
		hasher.api.Mul(hiEvenS, 1<<32),
		hasher.api.Mul(lowOddS, 1<<1),
		hasher.api.Mul(hiOddS, 1<<33),
	)
	hasher.api.AssertIsEqual(x, rec)
	odd = hasher.api.Add(lowOdd, hasher.api.Mul(hiOdd, 1<<16))
	even = hasher.api.Add(lowEven, hasher.api.Mul(hiEven, 1<<16))
	return
}

func (hasher *Hasher) unspreadIntoSpread(x frontend.Variable) (odd, even frontend.Variable) {
	r, _ := hasher.api.NewHint(func(field *big.Int, inputs []*big.Int, results []*big.Int) error {
		f := inputs[0].Int64()
		e, o := int64(0), int64(0)
		for i := 0; i < 32; i++ {
			e |= ((f >> (2 * i)) & 1) << i
			o |= ((f >> (2*i + 1)) & 1) << i
		}
		*results[0] = *big.NewInt((o & 0xFFFF0000) >> 16)
		*results[1] = *big.NewInt(o & 0x0000FFFF)
		*results[2] = *big.NewInt((e & 0xFFFF0000) >> 16)
		*results[3] = *big.NewInt(e & 0x0000FFFF)
		return nil
	}, 4, x)
	hiOdd, lowOdd, hiEven, lowEven := r[0], r[1], r[2], r[3]
	hiOddS := hasher.spreads[16].Lookup(hiOdd)[0]
	lowOddS := hasher.spreads[16].Lookup(lowOdd)[0]
	hiEvenS := hasher.spreads[16].Lookup(hiEven)[0]
	lowEvenS := hasher.spreads[16].Lookup(lowEven)[0]
	rec := hasher.api.Add(
		lowEvenS,
		hasher.api.Mul(hiEvenS, 1<<32),
		hasher.api.Mul(lowOddS, 1<<1),
		hasher.api.Mul(hiOddS, 1<<33),
	)
	hasher.api.AssertIsEqual(x, rec)
	odd = hasher.api.Add(lowOddS, hasher.api.Mul(hiOddS, 1<<32))
	even = hasher.api.Add(lowEvenS, hasher.api.Mul(hiEvenS, 1<<32))
	return
}

// carry is not checked!
func (hasher *Hasher) unsafeAddN(as []frontend.Variable) (carry frontend.Variable, result frontend.Variable) {
	sum := hasher.api.Add(as[0], as[1], as[2:]...)
	r, _ := hasher.api.NewHint(func(field *big.Int, inputs []*big.Int, results []*big.Int) error {
		in := inputs[0].Int64()
		*results[0] = *big.NewInt(in & ((1 << 16) - 1))
		*results[1] = *big.NewInt((in >> 16) & ((1 << 16) - 1))
		*results[2] = *big.NewInt(in >> 32)
		return nil
	}, 3, sum)
	hasher.spreads[16].Lookup(r[0])
	hasher.spreads[16].Lookup(r[1])
	res := hasher.api.Add(r[0], hasher.api.Mul(r[1], 1<<16))

	rec := hasher.api.Add(res, hasher.api.Mul(r[2], 1<<32))
	hasher.api.AssertIsEqual(sum, rec)
	return r[2], hasher.api.Add(r[0], hasher.api.Mul(r[1], 1<<16))
}

func (hasher *Hasher) add2(a, b frontend.Variable) frontend.Variable {
	carry, res := hasher.unsafeAddN([]frontend.Variable{a, b})
	zero := hasher.api.Mul(carry, hasher.api.Sub(carry, 1))
	hasher.api.AssertIsEqual(zero, 0)
	return res
}

func (hasher *Hasher) add4(a, b, c, d frontend.Variable) frontend.Variable {
	carry, res := hasher.unsafeAddN([]frontend.Variable{a, b, c, d})
	// carry is 0/1/2/3, which means y = 2*carry - 3 is -3/-1/1/3, which means y^2 is 1 or 9.
	y := hasher.api.Sub(hasher.api.Mul(2, carry), 3)
	ysq := hasher.api.Mul(y, y)
	zero := hasher.api.Mul(
		hasher.api.Sub(ysq, 1),
		hasher.api.Sub(ysq, 9),
	)
	hasher.api.AssertIsEqual(zero, 0)
	return res
}

func (hasher *Hasher) add6(a, b, c, d, e, f frontend.Variable) frontend.Variable {
	carry, res := hasher.unsafeAddN([]frontend.Variable{a, b, c, d, e, f})
	// carry is 0/1/2/3/4/5, which means y = 2*carry - 5 is -5/-3/-1/1/3/5, which means y^2 is 1/9/25.
	// So we check y^2 * (y^2 - 4) * (y^2 - 16) * (y^2 - 36) == 0
	y := hasher.api.Sub(hasher.api.Mul(2, carry), 5)
	ysq := hasher.api.Mul(y, y)
	zero := hasher.api.Mul(
		hasher.api.Sub(ysq, 1),
		hasher.api.Sub(ysq, 9),
		hasher.api.Sub(ysq, 25),
	)
	hasher.api.AssertIsEqual(zero, 0)
	return res
}

func (hasher *Hasher) add7(a, b, c, d, e, f, g frontend.Variable) frontend.Variable {
	carry, res := hasher.unsafeAddN([]frontend.Variable{a, b, c, d, e, f, g})
	// carry - 3 is -3/-2/-1/0/1/2/3, which means (carry -3)^2 is 0/1/4/9
	y := hasher.api.Sub(carry, 3)
	ysq := hasher.api.Mul(y, y)
	zero := hasher.api.Mul(
		ysq,
		hasher.api.Sub(ysq, 1),
		hasher.api.Sub(ysq, 4),
		hasher.api.Sub(ysq, 9),
	)
	hasher.api.AssertIsEqual(zero, 0)
	return res
}

func (hasher *Hasher) Schedule(w [16]frontend.Variable) [64]frontend.Variable {
	res := [64]frontend.Variable{}
	for i := 0; i < 16; i++ {
		res[i] = w[i]
	}
	for i := 16; i < 64; i++ {
		wi15s14, wi15s11, wi15s4, wi15s3 := hasher.splitAndSpread4(res[i-15], 14, 11, 4, 3)
		wi15rr7 := hasher.api.Add(
			wi15s11,
			hasher.api.Mul(wi15s14, 1<<22),
			hasher.api.Mul(wi15s3, 1<<50),
			hasher.api.Mul(wi15s4, 1<<56),
		)
		wi15rr18 := hasher.api.Add(
			wi15s14,
			hasher.api.Mul(wi15s3, 1<<28),
			hasher.api.Mul(wi15s4, 1<<34),
			hasher.api.Mul(wi15s11, 1<<42),
		)
		wi15rs3 := hasher.api.Add(
			wi15s4,
			hasher.api.Mul(wi15s11, 1<<8),
			hasher.api.Mul(wi15s14, 1<<30),
		)
		s0XorPlus := hasher.api.Add(wi15rr7, wi15rr18, wi15rs3)
		_, s0 := hasher.unspread(s0XorPlus)

		wi2s13, wi2s2, wi2s7, wi2s10 := hasher.splitAndSpread4(res[i-2], 13, 2, 7, 10)
		wi2rr17 := hasher.api.Add(
			wi2s2,
			hasher.api.Mul(wi2s13, 1<<4),
			hasher.api.Mul(wi2s10, 1<<30),
			hasher.api.Mul(wi2s7, 1<<50),
		)
		wi2rr19 := hasher.api.Add(
			wi2s13,
			hasher.api.Mul(wi2s10, 1<<26),
			hasher.api.Mul(wi2s7, 1<<46),
			hasher.api.Mul(wi2s2, 1<<60),
		)
		wi2rs10 := hasher.api.Add(
			wi2s7,
			hasher.api.Mul(wi2s2, 1<<14),
			hasher.api.Mul(wi2s13, 1<<18),
		)
		s1XorPlus := hasher.api.Add(wi2rr17, wi2rr19, wi2rs10)
		_, s1 := hasher.unspread(s1XorPlus)
		res[i] = hasher.add4(res[i-16], s0, res[i-7], s1)
	}
	return res
}

func (hasher *Hasher) Permute(H [8]frontend.Variable, chunk [16]frontend.Variable) [8]frontend.Variable {
	w := hasher.Schedule(chunk)
	a := H[0]
	b := H[1]
	c := H[2]
	d := H[3]
	e := H[4]
	f := H[5]
	g := H[6]
	h := H[7]
	for i := 0; i < 64; i++ {
		es7, es14, es5, es6 := hasher.splitAndSpread4(e, 7, 14, 5, 6)
		err6 := hasher.api.Add(
			es5,
			hasher.api.Mul(es14, 1<<10),
			hasher.api.Mul(es7, 1<<38),
			hasher.api.Mul(es6, 1<<52),
		)
		err11 := hasher.api.Add(
			es14,
			hasher.api.Mul(es7, 1<<28),
			hasher.api.Mul(es6, 1<<42),
			hasher.api.Mul(es5, 1<<54),
		)
		err25 := hasher.api.Add(
			es7,
			hasher.api.Mul(es6, 1<<14),
			hasher.api.Mul(es5, 1<<26),
			hasher.api.Mul(es14, 1<<36),
		)
		S1S := hasher.api.Add(err6, err11, err25)
		_, S1 := hasher.unspread(S1S)

		es := hasher.api.Add(
			es6,
			hasher.api.Mul(es5, 1<<12),
			hasher.api.Mul(es14, 1<<22),
			hasher.api.Mul(es7, 1<<50),
		)
		fs := hasher.spread(f)
		eAndFs, _ := hasher.unspreadIntoSpread(hasher.api.Add(es, fs))
		gs := hasher.spread(g)
		notEs := hasher.api.Sub(0x5555555555555555, es)
		notEandG, _ := hasher.unspreadIntoSpread(hasher.api.Add(notEs, gs))
		_, ch := hasher.unspread(hasher.api.Add(eAndFs, notEandG))

		as10, as9, as11, as2 := hasher.splitAndSpread4(a, 10, 9, 11, 2)
		arr2 := hasher.api.Add(
			as11,
			hasher.api.Mul(as9, 1<<22),
			hasher.api.Mul(as10, 1<<40),
			hasher.api.Mul(as2, 1<<60),
		)
		arr13 := hasher.api.Add(
			as9,
			hasher.api.Mul(as10, 1<<18),
			hasher.api.Mul(as2, 1<<38),
			hasher.api.Mul(as11, 1<<42),
		)
		arr22 := hasher.api.Add(
			as10,
			hasher.api.Mul(as2, 1<<20),
			hasher.api.Mul(as11, 1<<24),
			hasher.api.Mul(as9, 1<<46),
		)
		S0S := hasher.api.Add(arr2, arr13, arr22)
		_, S0 := hasher.unspread(S0S)

		as := hasher.api.Add(
			as2,
			hasher.api.Mul(as11, 1<<4),
			hasher.api.Mul(as9, 1<<26),
			hasher.api.Mul(as10, 1<<44),
		)
		bs := hasher.spread(b)
		cs := hasher.spread(c)
		maj, _ := hasher.unspread(hasher.api.Add(as, bs, cs))

		h = g
		g = f
		f = e
		e = hasher.add6(d, h, S1, ch, K[i], w[i])
		d = c
		c = b
		b = a
		a = hasher.add7(h, S1, ch, K[i], w[i], S0, maj)
	}
	res := [8]frontend.Variable{}
	res[0] = hasher.add2(H[0], a)
	res[1] = hasher.add2(H[1], b)
	res[2] = hasher.add2(H[2], c)
	res[3] = hasher.add2(H[3], d)
	res[4] = hasher.add2(H[4], e)
	res[5] = hasher.add2(H[5], f)
	res[6] = hasher.add2(H[6], g)
	res[7] = hasher.add2(H[7], h)
	return res
}

func Sha256Test(H [8]uint32, input [16]uint32) [8]uint32 {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = input[i]
	}
	for i := 16; i < 64; i++ {
		s0 := ((w[i-15] >> 7) | (w[i-15] << (32 - 7))) ^
			((w[i-15] >> 18) | (w[i-15] << (32 - 18))) ^
			(w[i-15] >> 3)
		w[i] = s0
		s1 := ((w[i-2] >> 17) | (w[i-2] << (32 - 17))) ^
			((w[i-2] >> 19) | (w[i-2] << (32 - 19))) ^
			(w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	a := H[0]
	b := H[1]
	c := H[2]
	d := H[3]
	e := H[4]
	f := H[5]
	g := H[6]
	h := H[7]

	for i := 0; i < 64; i++ {
		S1 := ((e >> 6) | (e << (32 - 6))) ^
			((e >> 11) | (e << (32 - 11))) ^
			((e >> 25) | (e << (32 - 25)))
		ch := (e & f) ^ (^e & g)
		temp1 := h + S1 + ch + K[i] + w[i]
		S0 := ((a >> 2) | (a << (32 - 2))) ^
			((a >> 13) | (a << (32 - 13))) ^
			((a >> 22) | (a << (32 - 22)))
		maj := (a & b) ^ (a & c) ^ (b & c)
		temp2 := S0 + maj

		h = g
		g = f
		f = e
		e = d + temp1
		d = c
		c = b
		b = a
		a = temp1 + temp2
	}

	res := [8]uint32{}
	res[0] = H[0] + a
	res[1] = H[1] + b
	res[2] = H[2] + c
	res[3] = H[3] + d
	res[4] = H[4] + e
	res[5] = H[5] + f
	res[6] = H[6] + g
	res[7] = H[7] + h

	return res
}

type Circuit struct {
	Iters  int
	H      [8]frontend.Variable
	Input  [16]frontend.Variable
	Output [8]frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	hasher := NewHasher(api)
	r := c.H
	for i := 0; i < c.Iters; i++ {
		r = hasher.Permute(r, c.Input)
	}
	for i := 0; i < 8; i++ {
		api.AssertIsEqual(c.Output[i], r[i])
	}
	return nil
}

func main() {
	fmt.Println("hello")
	o := Sha256Test(
		[8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
		[16]uint32{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	fmt.Print("{")
	for i := 0; i < 8; i++ {
		fmt.Print(o[i], ",")
	}
	fmt.Println("}")

	logger.Disable()

	lastCst := 0
	for i := 0; i < 37; i++ {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{Iters: i + 1})
		if err != nil {
			panic(err)
		}
		newCst := ccs.GetNbConstraints()

		fmt.Println(i, "\t", newCst, "\t", newCst-lastCst, "\t", int(float64(newCst)/float64(i+1)))
		lastCst = newCst
	}
}
