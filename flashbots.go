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
	DefaultRelayURL  = "https://relay.flashbots.net"
	TestRelayURL     = "https://relay-goerli.flashbots.net"
	FlashbotXHeader  = "X-Flashbots-Signature"
	MethodUserStats  = "flashbots_getUserStats"
	MethodSendBundle = "eth_sendBundle"
	MethodCallBundle = "eth_callBundle"
	Json             = "application/json"
	Post             = "POST"
)

type FlashbotsProvider struct {
	RelayURL   string
	SigningKey *ecdsa.PrivateKey
	WalletKey  *ecdsa.PrivateKey
}

type FlashbotsOptions struct {
	MinTimestamp      int64
	MaxTimestamp      int64
	RevertingTxHashes []string
}

type FlashbotsSendBundleParams struct {
	Transactions      []string `json:"txs"`
	BlockNumber       string   `json:"blockNumber"`
	MinTimestamp      int64    `json:"minTimestamp,omitempty"`
	MaxTimestamp      int64    `json:"maxTimestamp,omitempty"`
	RevertingTxHashes []string `json:"revertingTxHashes,omitempty"`
}

type FlashbotsCallBundleParams struct {
	Transactions     []string `json:"txs"`
	BlockNumber      string   `json:"blockNumber"`
	StateBlockNumber string   `json:"stateBlockNumber"`
	Timestamp        int64    `json:"timestamp,omitempty"`
}

type FlashbotsSendBundleResponse struct {
	ID      uint          `json:"id"`
	Version string        `json:"jsonrpc"`
	Result  *bundleResult `json:"result"`
	Raw     string
}

type FlashbotsCallBundleResponse struct {
	ID      uint         `json:"id"`
	Version string       `json:"jsonrpc"`
	Result  *callResult  `json:"result"`
	Error   *errorResult `json:"error"`
	Raw     string
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

type FlashbotsErrorResponse struct {
	Result map[string]string `json:"error"`
}

func NewFlashbotsProvider(signingKey *ecdsa.PrivateKey, walletKey *ecdsa.PrivateKey, relayURL string) *FlashbotsProvider {
	if relayURL == "" {
		relayURL = DefaultRelayURL
	}
	return &FlashbotsProvider{
		RelayURL:   relayURL,
		SigningKey: signingKey,
		WalletKey:  walletKey,
	}
}

func NewFlashbotsSendBundleParams(txs []string, blockNumber uint64, opts *FlashbotsOptions) *FlashbotsSendBundleParams {
	params := FlashbotsSendBundleParams{
		Transactions: txs,
		BlockNumber:  "0x0",
	}

	if blockNumber > 0 {
		params.BlockNumber = fmt.Sprintf("0x%x", blockNumber)
	}
	if opts.MinTimestamp > 0 {
		params.MinTimestamp = opts.MinTimestamp
	}
	if opts.MaxTimestamp > 0 {
		params.MaxTimestamp = opts.MaxTimestamp
	}
	if opts.RevertingTxHashes != nil {
		params.RevertingTxHashes = opts.RevertingTxHashes
	}

	return &params
}

func NewFlashbotsCallBundleParams(txs []string, blockNumber uint64, timestamp int64) *FlashbotsCallBundleParams {
	params := FlashbotsCallBundleParams{
		Transactions:     txs,
		BlockNumber:      fmt.Sprintf("0x%x", blockNumber),
		StateBlockNumber: "latest",
	}

	if timestamp > 0 {
		params.Timestamp = timestamp
	}

	return &params
}

func (provider *FlashbotsProvider) SendBundle(transactions []string, blockNumber *big.Int, opts *FlashbotsOptions) (*FlashbotsSendBundleResponse, error) {

	params := []interface{}{
		NewFlashbotsSendBundleParams(transactions, blockNumber.Uint64(), opts),
	}

	res, err := provider.sendRequest(provider.RelayURL, MethodSendBundle, params)
	if err != nil {
		return nil, err
	}

	response := FlashbotsSendBundleResponse{}
	response.Raw = string(res)
	err = json.Unmarshal(res, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (provider *FlashbotsProvider) CallBundle(transactions []string, blockNumber *big.Int, minTimestamp int64) (*FlashbotsCallBundleResponse, error) {

	params := []interface{}{
		NewFlashbotsCallBundleParams(transactions, blockNumber.Uint64(), minTimestamp),
	}

	res, err := provider.sendRequest(provider.RelayURL, MethodCallBundle, params)
	if err != nil {
		return nil, err
	}

	response := FlashbotsCallBundleResponse{}
	response.Raw = string(res)
	err = json.Unmarshal(res, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// Similar to normal CallBundle, but params are formatted differently
func (provider *FlashbotsProvider) CallBundleLocal(transactions []string, blockNumber *big.Int, minTimestamp int64) (*FlashbotsCallBundleResponse, error) {
	params := []interface{}{
		transactions,
		fmt.Sprintf("0x%x", blockNumber.Uint64()),
		"latest",
	}

	res, err := provider.sendRequest(provider.RelayURL, MethodCallBundle, params)
	if err != nil {
		return nil, err
	}

	response := FlashbotsCallBundleResponse{}
	response.Raw = string(res)
	err = json.Unmarshal(res, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (provider *FlashbotsProvider) Simulate(transactions []string, blockNumber *big.Int, minTimestamp int64) (*FlashbotsCallBundleResponse, error) {

	if provider.RelayURL[0:16] == "http://localhost" || provider.RelayURL[0:16] == "http://127.0.0.1" {
		return provider.CallBundleLocal(transactions, blockNumber, minTimestamp)
	}

	return provider.CallBundle(transactions, blockNumber, minTimestamp)
}

func (provider *FlashbotsProvider) sendRequest(relay string, method string, params []interface{}) ([]byte, error) {
	mevHTTPClient := &http.Client{
		Timeout: time.Second * 5,
	}

	payload, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})

	req, err := http.NewRequest(Post, relay, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	fbHeader, _ := provider.flashbotHeader(payload)
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

func (provider *FlashbotsProvider) flashbotHeader(payload []byte) (string, error) {

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

func (r *FlashbotsCallBundleResponse) HasError() error {
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

func (r *FlashbotsCallBundleResponse) EffectiveGasPrice() (*big.Int, error) {

	gu := new(big.Int).SetUint64(r.Result.TotalGasUsed)
	gp, ok := new(big.Int).SetString(r.Result.CoinbaseDiff, 10)
	if !ok {
		return nil, errors.New("Invalid value returned for CoinbaseDiff")
	}

	wei := new(big.Int).Div(gp, gu)
	return wei, nil
}

func buildPayload(method string, params interface{}) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  []interface{}{params},
	})
}
