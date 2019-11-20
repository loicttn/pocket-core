package types

import (
	"bytes"
	"fmt"
	"time"

	"github.com/pokt-network/posmint/codec"
	"github.com/pokt-network/posmint/x/params"
)

// POS params default values
const (
	DefaultUnstakingTime          = time.Hour * 24 * 7 * 3
	DefaultMaxApplications uint64 = 100000
	DefaultMinStake        int64  = 1
)

// nolint - Keys for parameter access
var (
	KeyUnstakingTime       = []byte("AppUnstakingTime")
	KeyMaxApplications     = []byte("MaxApplications")
	KeyApplicationMinStake = []byte("ApplicationStakeMinimum")
)

var _ params.ParamSet = (*Params)(nil)

// Params defines the high level settings for pos module
type Params struct {
	UnstakingTime   time.Duration `json:"unstaking_time" yaml:"unstaking_time"`       // duration of unstaking
	MaxApplications uint64        `json:"max_applications" yaml:"max_applications"`   // maximum number of applications
	AppStakeMin     int64         `json:"app_stake_minimum" yaml:"app_stake_minimum"` // minimum amount needed to stake
}

// Implements params.ParamSet
func (p *Params) ParamSetPairs() params.ParamSetPairs {
	return params.ParamSetPairs{
		{Key: KeyUnstakingTime, Value: &p.UnstakingTime},
		{Key: KeyMaxApplications, Value: &p.MaxApplications},
		{Key: KeyApplicationMinStake, Value: &p.AppStakeMin},
	}
}

// DefaultParams returns a default set of parameters.
func DefaultParams() Params {
	return Params{
		UnstakingTime:   DefaultUnstakingTime,
		MaxApplications: DefaultMaxApplications,
		AppStakeMin:     DefaultMinStake,
	}
}

// validate a set of params
func (p Params) Validate() error {
	if p.MaxApplications == 0 {
		return fmt.Errorf("staking parameter MaxApplications must be a positive integer")
	}
	if p.AppStakeMin < DefaultMinStake {
		return fmt.Errorf("staking parameter StakeMimimum must be a positive integer")
	}
	return nil
}

// Checks the equality of two param objects
func (p Params) Equal(p2 Params) bool {
	bz1 := ModuleCdc.MustMarshalBinaryLengthPrefixed(&p)
	bz2 := ModuleCdc.MustMarshalBinaryLengthPrefixed(&p2)
	return bytes.Equal(bz1, bz2)
}

// String returns a human readable string representation of the parameters.
func (p Params) String() string {
	return fmt.Sprintf(`Params:
  Unstaking Time:          %s
  Max Applications:          %d
  Minimum Stake:     	   %d,`,
		p.UnstakingTime,
		p.MaxApplications,
		p.AppStakeMin, )
}

// unmarshal the current pos params value from store key or panic
func MustUnmarshalParams(cdc *codec.Codec, value []byte) Params {
	p, err := UnmarshalParams(cdc, value)
	if err != nil {
		panic(err)
	}
	return p
}

// unmarshal the current pos params value from store key
func UnmarshalParams(cdc *codec.Codec, value []byte) (params Params, err error) {
	err = cdc.UnmarshalBinaryLengthPrefixed(value, &params)
	if err != nil {
		return
	}
	return
}
