package flashbots

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	DefaultRelayURL = "https://relay.flashbots.net"
	TestRelayURL    = "https://relay-goerli.flashbots.net"

	MethodUserStats  = "flashbots_getUserStats"
	MethodSendBundle = "eth_sendBundle"
	MethodCallBundle = "eth_callBundle"

	FlashbotXHeader = "X-Flashbots-Signature"
	Json            = "application/json"
	Post            = "POST"
)

type Provider struct {
	RelayURL   string
	SigningKey *ecdsa.PrivateKey
	WalletKey  *ecdsa.PrivateKey
}

type Options struct {
	MinTimestamp      int64
	MaxTimestamp      int64
	RevertingTxHashes []string
}

type SendBundleParams struct {
	Transactions      []string `json:"txs"`
	BlockNumber       string   `json:"blockNumber"`
	MinTimestamp      int64    `json:"minTimestamp,omitempty"`
	MaxTimestamp      int64    `json:"maxTimestamp,omitempty"`
	RevertingTxHashes []string `json:"revertingTxHashes,omitempty"`
}

type CallBundleParams struct {
	Transactions     []string `json:"txs"`
	BlockNumber      string   `json:"blockNumber"`
	StateBlockNumber string   `json:"stateBlockNumber"`
	Timestamp        int64    `json:"timestamp,omitempty"`
}

type SendBundleResponse struct {
	ID      uint          `json:"id"`
	Version string        `json:"jsonrpc"`
	Result  *bundleResult `json:"result"`
	Raw     string
}

type CallBundleResponse struct {
	ID      uint         `json:"id"`
	Version string       `json:"jsonrpc"`
	Result  *callResult  `json:"result"`
	Error   *errorResult `json:"error"`
	Raw     string
}

type ErrorResponse struct {
	Result map[string]string `json:"error"`
}

type errorResult struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

type bundleResult struct {
	BundleHash string `json:"bundleHash"`
}

type txResult struct {
	CoinbaseDiff      string `json:"coinbaseDiff"`
	EthSentToCoinbase string `json:"ethSentToCoinbase"`
	FromAddress       string `json:"fromAddress"`
	GasFees           string `json:"gasFees"`
	GasPrice          string `json:"gasPrice"`
	GasUsed           uint64 `json:"gasUsed"`
	ToAddress         string `json:"toAddress"`
	TxHash            string `json:"txHash"`
	Value             string `json:"value"`
	Error             string `json:"error,omitempty"`
}

type callResult struct {
	BundleGasPrice    string     `json:"bundleGasPrice"`
	BundleHash        string     `json:"bundleHash"`
	CoinbaseDiff      string     `json:"coinbaseDiff"`
	EthSentToCoinbase string     `json:"ethSentToCoinbase"`
	GasFees           string     `json:"gasFees"`
	Results           []txResult `json:"results"`
	StateBlockNumber  uint64     `json:"stateBlockNumber"`
	TotalGasUsed      uint64     `json:"totalGasUsed"`
}

func NewProvider(signingKey *ecdsa.PrivateKey, walletKey *ecdsa.PrivateKey, relayURL string) *Provider {
	if relayURL == "" {
		relayURL = DefaultRelayURL
	}
	return &Provider{
		RelayURL:   relayURL,
		SigningKey: signingKey,
		WalletKey:  walletKey,
	}
}

func (provider *Provider) SendBundle(transactions []string, blockNumber *big.Int, opts *Options) (*SendBundleResponse, error) {

	params := SendBundleParams{
		Transactions: transactions,
		BlockNumber:  fmt.Sprintf("0x%x", blockNumber),
	}

	if opts != nil && opts.MinTimestamp > 0 {
		params.MinTimestamp = opts.MinTimestamp
	}
	if opts != nil && opts.MaxTimestamp > 0 {
		params.MaxTimestamp = opts.MaxTimestamp
	}
	if opts != nil && opts.RevertingTxHashes != nil {
		params.RevertingTxHashes = opts.RevertingTxHashes
	}

	res, err := provider.sendRequest(provider.RelayURL, MethodSendBundle, []interface{}{params})
	if err != nil {
		return nil, err
	}

	response := SendBundleResponse{Raw: string(res)}
	err = json.Unmarshal(res, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (provider *Provider) CallBundle(transactions []string, blockNumber *big.Int, stateBlockNumber string, minTimestamp int64) (*CallBundleResponse, error) {

	params := CallBundleParams{
		Transactions:     transactions,
		BlockNumber:      fmt.Sprintf("0x%x", blockNumber.Uint64()),
		StateBlockNumber: stateBlockNumber,
	}

	if minTimestamp > 0 {
		params.Timestamp = minTimestamp
	}

	res, err := provider.sendRequest(provider.RelayURL, MethodCallBundle, []interface{}{params})
	if err != nil {
		return nil, err
	}

	response := CallBundleResponse{Raw: string(res)}
	err = json.Unmarshal(res, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// Similar to normal CallBundle, but params are formatted differently for passing to the mev-geth RPC endpoint directly
func (provider *Provider) CallBundleLocal(transactions []string, blockNumber *big.Int, stateBlockNumber string, minTimestamp int64) (*CallBundleResponse, error) {
	params := []interface{}{
		transactions,
		fmt.Sprintf("0x%x", blockNumber.Uint64()),
		stateBlockNumber,
	}

	res, err := provider.sendRequest(provider.RelayURL, MethodCallBundle, params)
	if err != nil {
		return nil, err
	}

	response := CallBundleResponse{Raw: string(res)}
	err = json.Unmarshal(res, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (provider *Provider) Simulate(transactions []string, blockNumber *big.Int, stateBlockNumber string, minTimestamp int64) (*CallBundleResponse, error) {

	if provider.RelayURL[0:16] == "http://localhost" || provider.RelayURL[0:16] == "http://127.0.0.1" {
		return provider.CallBundleLocal(transactions, blockNumber, stateBlockNumber, minTimestamp)
	}

	return provider.CallBundle(transactions, blockNumber, stateBlockNumber, minTimestamp)
}

func (r *CallBundleResponse) HasError() error {
	if r.Error != nil {
		return errors.New(fmt.Sprintf("Error from simulate: %s\n", r.Error.Message))
	}

	if r.Result == nil || len(r.Result.Results) == 0 {
		return errors.New(fmt.Sprintf("Invalid response from simulate: %s\n", r.Raw))
	}

	for _, result := range r.Result.Results {
		if result.Error != "" {
			return errors.New(fmt.Sprintf("Error from simulate [%s]: %s\n", result.TxHash, result.Error))
		}
	}

	return nil
}

func (r *CallBundleResponse) EffectiveGasPrice() (*big.Int, error) {

	gu := new(big.Int).SetUint64(r.Result.TotalGasUsed)
	gp, ok := new(big.Int).SetString(r.Result.CoinbaseDiff, 10)
	if !ok {
		return nil, errors.New("Invalid value returned for CoinbaseDiff")
	}

	wei := new(big.Int).Div(gp, gu)
	return wei, nil
}

func (provider *Provider) sendRequest(relay string, method string, params []interface{}) ([]byte, error) {
	mevHTTPClient := &http.Client{
		Timeout: time.Second * 5,
	}

	payload, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(Post, relay, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	fbHeader, err := provider.flashbotHeader(payload)
	if err != nil {
		return nil, err
	}

	req.Header.Add("content-type", Json)
	req.Header.Add("Accept", Json)
	req.Header.Add(FlashbotXHeader, fbHeader)

	resp, err := mevHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(resp.Body)
}

func (provider *Provider) flashbotHeader(payload []byte) (string, error) {

	hashedPayload := crypto.Keccak256Hash(payload).Hex()
	signature, err := crypto.Sign(
		crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n"+strconv.Itoa(len(hashedPayload))+hashedPayload)),
		provider.SigningKey,
	)
	if err != nil {
		return "", err
	}

	return crypto.PubkeyToAddress(provider.SigningKey.PublicKey).Hex() +
		":" + hexutil.Encode(signature), nil
}
