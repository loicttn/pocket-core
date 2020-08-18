package pocketcore

import (
	"encoding/json"
	"math/rand"
	"time"

	"github.com/pokt-network/pocket-core/codec"
	sdk "github.com/pokt-network/pocket-core/types"
	"github.com/pokt-network/pocket-core/types/module"
	"github.com/pokt-network/pocket-core/x/pocketcore/keeper"
	"github.com/pokt-network/pocket-core/x/pocketcore/types"
	abci "github.com/tendermint/tendermint/abci/types"
)

// type check to ensure the interface is properly implemented
var (
	_ module.AppModule      = AppModule{}
	_ module.AppModuleBasic = AppModuleBasic{}
)

// "AppModuleBasic" - The fundamental building block of a sdk module
type AppModuleBasic struct{}

// "Name" - Returns the name of the module
func (AppModuleBasic) Name() string {
	return types.ModuleName
}

// "RegisterCodec" - Registers the codec for the module
func (AppModuleBasic) RegisterCodec(amino *codec.LegacyAmino, proto *codec.ProtoCodec) {
	types.RegisterCodec(amino, proto)
}

// "DefaultGenesis" - Returns the default genesis for the module
func (AppModuleBasic) DefaultGenesis() json.RawMessage {
	return types.ModuleCdc.MustMarshalJSON(types.DefaultGenesisState())
}

// "ValidateGenesis" - Validation check for genesis state bytes
func (AppModuleBasic) ValidateGenesis(bytes json.RawMessage) error {
	var data types.GenesisState
	err := types.ModuleCdc.UnmarshalJSON(bytes, &data)
	if err != nil {
		return err
	}
	// Once json successfully marshalled, passes along to genesis.go
	return types.ValidateGenesis(data)
}

// "AppModule" - The higher level building block for a module
type AppModule struct {
	AppModuleBasic               // a fundamental structure for all mods
	keeper         keeper.Keeper // responsible for store operations
}

// "NewAppModule" - Creates a new AppModule Object
func NewAppModule(keeper keeper.Keeper) AppModule {
	return AppModule{
		AppModuleBasic: AppModuleBasic{},
		keeper:         keeper,
	}
}

// "RegisterInvariants" - Unused crisis checking
func (am AppModule) RegisterInvariants(ir sdk.InvariantRegistry) {}

// "Route" - returns the route of the module
func (am AppModule) Route() string {
	return types.RouterKey
}

// "NewHandler" - returns the handler for the module
func (am AppModule) NewHandler() sdk.Handler {
	return NewHandler(am.keeper)
}

// "QuerierRoute" - returns the route of the module for queries
func (am AppModule) QuerierRoute() string {
	return types.ModuleName
}

// "NewQuerierHandler" - returns the query handler for the module
func (am AppModule) NewQuerierHandler() sdk.Querier {
	return keeper.NewQuerier(am.keeper)
}

// "BeginBlock" - Functionality that is called at the beginning of (every) block
func (am AppModule) BeginBlock(ctx sdk.Ctx, req abci.RequestBeginBlock) {
	if am.keeper.IsSessionBlock(ctx) && ctx.BlockHeight() != 1 {
		go func() {
			// use this sleep timer to bypass the beginBlock lock over transactions
			time.Sleep(time.Duration(rand.Intn(5000)) * time.Millisecond)
			// auto send the proofs
			am.keeper.SendClaimTx(ctx, am.keeper, am.keeper.TmNode, ClaimTx)
			// auto claim the proofs
			am.keeper.SendProofTx(ctx, am.keeper.TmNode, ProofTx)
			// clear session cache and db
			types.ClearSessionCache()
		}()
	}
	go func() {
		// flush the cache periodically
		types.FlushCache()
	}()
	// delete the expired claims
	am.keeper.DeleteExpiredClaims(ctx)
}

// "EndBlock" - Functionality that is called at the end of (every) block
func (am AppModule) EndBlock(sdk.Ctx, abci.RequestEndBlock) []abci.ValidatorUpdate {
	return []abci.ValidatorUpdate{}
}

// "InitGenesis" - Inits the module genesis from raw json
func (am AppModule) InitGenesis(ctx sdk.Ctx, data json.RawMessage) []abci.ValidatorUpdate {
	var genesisState types.GenesisState
	if data == nil {
		genesisState = types.DefaultGenesisState()
	} else {
		types.ModuleCdc.MustUnmarshalJSON(data, &genesisState)
	}
	return InitGenesis(ctx, am.keeper, genesisState)
}

// "ExportGenesis" - Exports the genesis from raw json
func (am AppModule) ExportGenesis(ctx sdk.Ctx) json.RawMessage {
	gs := ExportGenesis(ctx, am.keeper)
	return types.ModuleCdc.MustMarshalJSON(gs)
}
