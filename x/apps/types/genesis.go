package types

// GenesisState - all staking state that must be provided at genesis
//type GenesisState struct {
//	Params       Params       `json:"params" yaml:"params"`
//	Applications Applications `json:"applications" yaml:"applications"`
//	Exported     bool         `json:"exported" yaml:"exported"`
//}

//// PrevState application power, needed for application set update logic
//type PrevStatePowerMapping struct {
//	Address sdk.Address
//	Power   int64
//}

// get raw genesis raw message for testing
func DefaultGenesisState() GenesisState {
	dp := DefaultParams()
	return GenesisState{
		Params:       &dp,
		Applications: make(Applications, 0),
	}
}
