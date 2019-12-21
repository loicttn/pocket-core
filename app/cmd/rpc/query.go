package rpc

import (
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"github.com/pokt-network/pocket-core/app"
	appTypes "github.com/pokt-network/pocket-core/x/apps/types"
	nodeTypes "github.com/pokt-network/pocket-core/x/nodes/types"
	"net/http"
	"strings"
)

func Version(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	WriteResponse(w, APIVersion, r.URL.Path, r.Host)
}

type queryBlockParams struct {
	Height int64 `json:"height"`
}

func Block(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryBlockParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryBlock(params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(res), r.URL.Path, r.Host)
}

type queryTxParmas struct {
	Hash string `json:"string"`
}

func Tx(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryTxParmas{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryTx(params.Hash)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
	}
	s, er := json.MarshalIndent(res, "", "  ")
	if er != nil {
		WriteErrorResponse(w, 400, er.Error())
		return
	}
	WriteResponse(w, string(s), r.URL.Path, r.Host)
}

func Height(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	res, err := app.QueryHeight()
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(res), r.URL.Path, r.Host)
}

type queryBalanceParams struct {
	Height  int64  `json:"height"`
	Address string `json:"address"`
}

func Balance(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryBalanceParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryBalance(params.Address, params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	s, err := app.Cdc.MarshalJSON(res)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(s), r.URL.Path, r.Host)
}

type queryNodesParams struct {
	Height        int64
	StakingStatus string
}

func Nodes(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryNodesParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	var res nodeTypes.Validators
	var err error
	switch strings.ToLower(params.StakingStatus) {
	case "":
		// no status passed
		res, err = app.QueryAllNodes(params.Height)
	case "staked":
		// staked nodes
		res, err = app.QueryStakedNodes(params.Height)
	case "unstaked":
		// unstaked nodes
		res, err = app.QueryUnstakedNodes(params.Height)
	case "unstaking":
		// unstaking nodes
		res, err = app.QueryUnstakingNodes(params.Height)
	default:
		panic("invalid staking status, can be staked, unstaked, unstaking, or empty")
	}
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	j, err := res.JSON()
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
	}
	WriteResponse(w, string(j), r.URL.Path, r.Host)
}

func Node(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryBalanceParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryNode(params.Address, params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	j, err := res.MarshalJSON()
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(j), r.URL.Path, r.Host)
}

func NodeParams(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryBlockParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryNodeParams(params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	j, err := app.Cdc.MarshalJSON(res)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(j), r.URL.Path, r.Host)
}

func NodeProofs(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryBalanceParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryProofs(params.Address, params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	j, err := app.Cdc.MarshalJSON(res)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(j), r.URL.Path, r.Host)
}

type queryNodeProof struct {
	Address      string `json:"address"`
	Blockchain   string `json:"blockchain"`
	AppPubKey    string `json:"app_pubkey"`
	SBlockHeight int64  `json:"session_block_height"`
	Height       int64  `json:"height"`
}

func NodeProof(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryNodeProof{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryProof(params.Blockchain, params.AppPubKey, params.Address, params.SBlockHeight, params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	j, err := app.Cdc.MarshalJSON(res)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(j), r.URL.Path, r.Host)
}

func Apps(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryNodesParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	var res appTypes.Applications
	var err error
	switch strings.ToLower(params.StakingStatus) {
	case "":
		// no status passed
		res, err = app.QueryAllApps(params.Height)
	case "staked":
		// staked nodes
		res, err = app.QueryStakedApps(params.Height)
	case "unstaked":
		// unstaked nodes
		res, err = app.QueryUnstakedApps(params.Height)
	case "unstaking":
		// unstaking nodes
		res, err = app.QueryUnstakingApps(params.Height)
	default:
		panic("invalid staking status, can be staked, unstaked, unstaking, or empty")
	}
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	j, err := res.JSON()
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
	}
	WriteResponse(w, string(j), r.URL.Path, r.Host)
}

func App(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryBalanceParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryApp(params.Address, params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	j, err := res.MarshalJSON()
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(j), r.URL.Path, r.Host)
}

func AppParams(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryBlockParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryAppParams(params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	j, err := app.Cdc.MarshalJSON(res)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(j), r.URL.Path, r.Host)
}

func PocketParams(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryBlockParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryPocketParams(params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	j, err := app.Cdc.MarshalJSON(res)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(j), r.URL.Path, r.Host)
}

func SupportedChains(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryBlockParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	res, err := app.QueryPocketSupportedBlockchains(params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	j, err := app.Cdc.MarshalJSON(res)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(j), r.URL.Path, r.Host)
}

type querySupplyResponse struct {
	NodeStaked    int64 `json:"node_staked"`
	AppStaked     int64 `json:"app_staked"`
	Dao           int64 `json:"dao"`
	TotalStaked   int64 `json:"total_staked"`
	TotalUnstaked int64 `json:"total_unstaked"`
	Total         int64 `json:"total"`
}

func Supply(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var params = queryBlockParams{}
	if err := PopModel(w, r, ps, params); err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	nodesStake, nodesUnstaked, err := app.QueryTotalNodeCoins(params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	appsStaked, appsUnstaked, err := app.QueryTotalAppCoins(params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	dao, err := app.QueryDaoBalance(params.Height)
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	totalStaked := nodesStake.Add(appsStaked)
	totalUnstaked := nodesUnstaked.Add(appsUnstaked).Add(dao) // todo error check this may be wrong
	total := totalStaked.Add(totalUnstaked)
	res, err := json.MarshalIndent(&querySupplyResponse{
		NodeStaked:    nodesStake.Int64(),
		AppStaked:     appsStaked.Int64(),
		Dao:           dao.Int64(),
		TotalStaked:   totalStaked.Int64(),
		TotalUnstaked: totalUnstaked.Int64(),
		Total:         total.Int64(),
	}, "", "  ")
	if err != nil {
		WriteErrorResponse(w, 400, err.Error())
		return
	}
	WriteResponse(w, string(res), r.URL.Path, r.Host)
}