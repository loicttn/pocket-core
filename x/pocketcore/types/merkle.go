package types

import (
	"bytes"
	"encoding/binary"
	"math"
	"reflect"
	"sort"
	"strconv"

	"golang.org/x/crypto/blake2b"
)

type Range struct {
	Lower uint64 `json:"lower"`
	Upper uint64 `json:"upper"`
}

func (r Range) Bytes() []byte {
	return append(uint64ToBytes(r.Lower), uint64ToBytes(r.Upper)...)
}

type proofAndRanges struct {
	hr []HashRange
	p  []Proof
}
type SortByProof proofAndRanges

func (a SortByProof) Len() int { return len(a.hr) }
func (a SortByProof) Swap(i, j int) {
	a.hr[i], a.hr[j] = a.hr[j], a.hr[i]
	a.p[i], a.p[j] = a.p[j], a.p[i]
}
func (a SortByProof) Less(i, j int) bool { return a.hr[i].Range.Upper < a.hr[j].Range.Upper }

// "uint64ToBytes" - convert the uint64 to bytes
func uint64ToBytes(a uint64) (bz []byte) {
	bz = make([]byte, 8)
	binary.LittleEndian.PutUint64(bz, a)
	return
}

// "HashRange" - A structure to represent the merkleHash and the range at an index in the merkle sum tree
type HashRange struct {
	Hash  []byte `json:"merkleHash"`
	Range Range  `json:"range"`
}

func (hr HashRange) isValidRange() bool {
	if hr.Range.Upper == 0 {
		return false
	}
	if hr.Range.Lower >= hr.Range.Upper {
		return false
	}
	return true
}

// "MerkleProof" - A structure used to verify a leaf of the tree.
type MerkleProof struct {
	TargetIndex int         `json:"index"`
	HashRanges  []HashRange `json:"hash_ranges"`
	Target      HashRange   `json:"target_range"`
}

// "Validate" - Verifies the Proof from the leaf/cousin node data, the merkle root, and the Proof object
func (mp MerkleProof) Validate(root HashRange, leaf Proof, totalRelays int64) (isValid bool) {
	// ensure root lower is zero
	if root.Range.Lower != 0 {
		return
	}
	// check if levels and total relays is valid
	numOfLevels, valid := levelsIsValid(len(mp.HashRanges), totalRelays)
	if !valid {
		return
	}
	// check to see that target merkleHash is leaf merkleHash
	if !bytes.Equal(mp.Target.Hash, merkleHash(leaf.Bytes())) {
		return
	}
	// check to see that target upper == decimal representation of merkleHash
	if mp.Target.Range.Upper != sumFromHash(mp.Target.Hash) {
		return
	}
	// execute the for loop for each level
	for i := 0; i < numOfLevels; i++ {
		// check for valid range
		if !mp.Target.isValidRange() {
			return
		}
		// get sibling from mp object
		sibling := mp.HashRanges[i]
		// check to see if sibling is within a valid range
		if !sibling.isValidRange() {
			return
		}
		if mp.TargetIndex%2 == 1 { // odd target index
			// target lower should be GTE sibling upper
			if mp.Target.Range.Lower != sibling.Range.Upper {
				return
			}
			// calculate the parent range and store it where the child used to be
			mp.Target.Range.Lower = sibling.Range.Lower
			// **upper stays the same**
			// generate the parent merkleHash and store it where the child used to be
			mp.Target.Hash = parentHash(sibling.Hash, mp.Target.Hash, mp.Target.Range)
		} else { // even index
			// target upper should be LTE sibling lower
			if mp.Target.Range.Upper != sibling.Range.Lower {
				return
			}
			// calculate the parent range and store it where the child used to be
			mp.Target.Range.Upper = sibling.Range.Upper
			// **lower stays the same**
			// generate the parent merkleHash and store it where the child used to be
			mp.Target.Hash = parentHash(mp.Target.Hash, sibling.Hash, mp.Target.Range)
		}
		// half the indices as we are going up one level
		mp.TargetIndex /= 2
	}
	// ensure root == verification for leaf and cousin
	return reflect.DeepEqual(root, mp.Target)
}

// "sumFromHash" - get leaf sum from merkleHash
func sumFromHash(hash []byte) uint64 {
	hashCopy := make([]byte, len(hash))
	copy(hashCopy, hash)
	return binary.LittleEndian.Uint64(hash[:8])
}

// "newLevelIsValid" - Ensure that the number of levels in the relayProof is valid
func levelsIsValid(leafNumOfLevels int, totalRelays int64) (numOfLevels int, isValid bool) {
	return leafNumOfLevels, nextPowerOfTwo(uint(totalRelays)) == uint(math.Pow(2, float64(leafNumOfLevels)))
}

// "nextPowrOfTwo" - Computes the next power of 2 given an u-integer
func nextPowerOfTwo(v uint) uint {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return v
}

// "GenerateProofs" - Generates the merkle Proof object from the leaf node data and the index
func GenerateProofs(p []Proof, index int) (mProof MerkleProof, leaf Proof) {
	data, proofs := structureProofs(p) // proofs are already sorted
	// make a copy of the data because the merkle proof function will manipulate the slice
	dataCopy := make([]HashRange, len(data))
	// Copy from the original map to the target map
	copy(dataCopy, data)
	// generate Proof for leaf
	mProof = merkleProof(data, index, &MerkleProof{})
	// reset leaf index
	mProof.TargetIndex = index
	// get the leaf
	leaf = proofs[index]
	// get the targetHashRange
	mProof.Target = dataCopy[index]
	// return merkleProofs object
	return
}

// "merkleProof" - recursive Proof function that generates the Proof object one level at a time
func merkleProof(data []HashRange, index int, p *MerkleProof) MerkleProof {
	if index%2 == 1 { // odd index so sibling to the left
		p.HashRanges = append(p.HashRanges, data[index-1])
	} else { // even index so sibling to the right
		p.HashRanges = append(p.HashRanges, data[index+1])
	}
	data, atRoot := levelUp(data)
	if !atRoot {
		// next level Entropy = previous index / 2 (
		merkleProof(data, index/2, p)
	}
	return *p
}

// "newParentHash" - Compute the merkleHash of the parent by hashing the hashes, sum and parent
func parentHash(hash1, hash2 []byte, r Range) []byte {
	return merkleHash(append(append(hash1, hash2...), r.Bytes()...))
}

// "merkleHash" - the merkleHash function used in the merkle tree
func merkleHash(data []byte) []byte {
	hash := blake2b.Sum256(data)
	return hash[:]
}

// "GenerateRoot" - generates the merkle root from leaf node data
func GenerateRoot(data []Proof) (r HashRange, sortedData []Proof) {
	// structure the leafs
	adjacentHashRanges, sortedProofs := sortAndStructure(data)
	// call the root function and return
	return root(adjacentHashRanges), sortedProofs
}

// "root" - Generates the root (highest level) from the merkleHash range data recursively
// CONTRACT: dataLength must be > 1 or this breaks
func root(data []HashRange) HashRange {
	data, atRoot := levelUp(data)
	if !atRoot {
		// if not at root continue to level up
		root(data)
	}
	// if at root return
	return data[0]
}

// "levelUp" - takes the previous level data and converts it to the next level data
func levelUp(data []HashRange) (nextLevelData []HashRange, atRoot bool) {
	for i, d := range data {
		// if odd element, skip
		if i%2 == 1 {
			continue
		}
		// calculate the parent range, the right child upper is new upper
		data[i/2].Range.Upper = data[i+1].Range.Upper
		// the left child lower is new lower
		data[i/2].Range.Lower = data[i].Range.Lower
		// calculate the parent merkleHash
		data[i/2].Hash = parentHash(d.Hash, data[i+1].Hash, data[i/2].Range)
	}
	// check to see if at root
	dataLen := len(data) / 2
	if dataLen == 1 {
		return data[:dataLen], true
	}
	return data[:dataLen], false
}

func sortAndStructure(proofs []Proof) (d []HashRange, sortedProofs []Proof) {
	// get the # of proofs
	numberOfProofs := len(proofs)
	// initialize the hashRange
	hashRanges := make([]HashRange, numberOfProofs)

	// sort the slice based on the numerical value of the upper value (just the decimal representation of the merkleHash)
	if hashRanges[0].Range.Upper == 0 {
		for i := range hashRanges {
			// save the merkleHash and sum of the Proof in the new tree slice
			hashRanges[i].Hash = merkleHash(proofs[i].Bytes())
			// get the inital sum (just the dec val of the merkleHash)
			hashRanges[i].Range.Upper = sumFromHash(hashRanges[i].Hash)
		}
	}
	sortedRangesAndProofs := proofAndRanges{hashRanges, proofs}
	sort.Sort(SortByProof(sortedRangesAndProofs))
	hashRanges, proofs = sortedRangesAndProofs.hr, sortedRangesAndProofs.p
	// keep track of previous upper (next values lower)
	lower := uint64(0)
	// set the lower values of each
	for i := range proofs {
		// the range is the previous
		hashRanges[i].Range.Lower = lower
		// update the lower
		lower = hashRanges[i].Range.Upper
	}
	// calculate the proper length of the merkle tree
	properLength := nextPowerOfTwo(uint(numberOfProofs))
	// generate padding to make it a proper merkle tree
	padding := make([]HashRange, int(properLength)-numberOfProofs)
	// add it to the merkleHash rangeds
	hashRanges = append(hashRanges, padding...)
	// add padding to the end of the hashRange
	for i := numberOfProofs; i < int(properLength); i++ {
		hashRanges[i] = HashRange{
			Hash:  merkleHash([]byte(strconv.Itoa(i))),
			Range: Range{Lower: lower, Upper: lower + 1},
		}
		lower = hashRanges[i].Range.Upper
	}
	return hashRanges, proofs
}

// "structureProofs" - structure hash ranges when proofs are already sorted
func structureProofs(proofs []Proof) (d []HashRange, sortedProofs []Proof) {
	// get the # of proofs
	numberOfProofs := len(proofs)
	// initialize the hashRange
	hashRanges := make([]HashRange, numberOfProofs)
	// keep track of previous upper (next values lower)
	lower := uint64(0)

	// sort the slice based on the numerical value of the upper value (just the decimal representation of the merkleHash)
	if hashRanges[0].Range.Upper == 0 {
		for i := range hashRanges {
			// save the merkleHash and sum of the Proof in the new tree slice
			hashRanges[i].Hash = merkleHash(proofs[i].Bytes())
			// get the inital sum (just the dec val of the merkleHash)
			hashRanges[i].Range.Upper = sumFromHash(hashRanges[i].Hash)
			// the range is the previous
			hashRanges[i].Range.Lower = lower
			// update the lower
			lower = hashRanges[i].Range.Upper
		}
	}

	properLength := nextPowerOfTwo(uint(numberOfProofs))
	// generate padding to make it a proper merkle tree
	padding := make([]HashRange, int(properLength)-numberOfProofs)
	// add it to the merkleHash rangeds
	hashRanges = append(hashRanges, padding...)
	// add padding to the end of the hashRange
	for i := numberOfProofs; i < int(properLength); i++ {
		hashRanges[i] = HashRange{
			Hash:  merkleHash([]byte(strconv.Itoa(i))),
			Range: Range{Lower: lower, Upper: lower + 1},
		}
		lower = hashRanges[i].Range.Upper
	}
	return hashRanges, proofs
}
