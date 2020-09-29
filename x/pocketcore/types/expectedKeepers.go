package types

import (
	sdk "github.com/pokt-network/pocket-core/types"
	appexported "github.com/pokt-network/pocket-core/x/apps/exported"
	nodesexported "github.com/pokt-network/pocket-core/x/nodes/exported"
)

type PosKeeper interface {
	RewardForRelays(ctx sdk.Ctx, relays sdk.BigInt, address sdk.Address) sdk.BigInt
	GetStakedTokens(ctx sdk.Ctx) sdk.BigInt
	Validator(ctx sdk.Ctx, addr sdk.Address) nodesexported.ValidatorI
	TotalTokens(ctx sdk.Ctx) sdk.BigInt
	BurnForChallenge(ctx sdk.Ctx, challenges sdk.BigInt, address sdk.Address)
	JailValidator(ctx sdk.Ctx, addr sdk.Address)
	AllValidators(ctx sdk.Ctx) (validators []nodesexported.ValidatorI)
	GetStakedValidators(ctx sdk.Ctx) (validators []nodesexported.ValidatorI)
	BlocksPerSession(ctx sdk.Ctx) (res int64)
	StakeDenom(ctx sdk.Ctx) (res string)
	GetValidatorsByChain(ctx sdk.Ctx, networkID string) (validators []nodesexported.ValidatorI)
}

type AppsKeeper interface {
	GetStakedTokens(ctx sdk.Ctx) sdk.BigInt
	Application(ctx sdk.Ctx, addr sdk.Address) appexported.ApplicationI
	AllApplications(ctx sdk.Ctx) (applications []appexported.ApplicationI)
	TotalTokens(ctx sdk.Ctx) sdk.BigInt
	JailApplication(ctx sdk.Ctx, addr sdk.Address)
}

type AuthKeeper interface {
	GetFee(ctx sdk.Ctx, msg sdk.Msg) sdk.BigInt
}
