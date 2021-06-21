# flashbots-bundle

This is a go library for simulating and sending bundles to the [Flashbots](https://flashbots.net/) mev-geth relay.

## Usage
Simulate Bundle
```go
start := time.Now()

signingKey, _ := crypto.HexToECDSA(flashbotsSigningKeyHex)
privateKey, _ := crypto.HexToECDSA(privateKeyHex)
publicKeyCrypto := privateKey.Public()
publicKey, _ := publicKey.(*ecdsa.publicKeyCrypto)

client, err = ethclient.Dial(providerURL)
if err != nil {
    log.Fatal(err)
}

// signedTxs is an array of signed transactions objects
// signedTxs []*types.Transaction
txs := []string{}
for _, tx := range signedTxs {
    data, err := tx.MarshalBinary()
    if err != nil {
        log.Fatal(err)
    }
    txs = append(txs, hexutil.Encode(data))
}

block, err := client.HeaderByNumber(context.Background(), nil)
if err != nil {
    log.Fatal(err)
}

fb := flashbots.NewProvider(signingKey, privateKey, flashbots.DefaultRelayURL)
resp, err := fb.Simulate(txs, block.Number, "latest", 0)
if err != nil {
    log.Fatal(err)
}

err = resp.HasError()
if err != nil {
    log.Fatal(err)
}

cb, _ := new(big.Float).SetString(resp.Result.CoinbaseDiff)
eth := new(big.Float).Quo(cb, big.NewFloat(math.Pow10(18)))
wei, _ := resp.EffectiveGasPrice()
gwei := toGwei(wei)

fmt.Printf("Simulation completed in %fs. Cost: %f eth, effective price: %d gwei\n", time.Since(start).Seconds(), eth, gwei)
```

Send Bundle
```go
signingKey, _ := crypto.HexToECDSA(flashbotsSigningKeyHex)
privateKey, _ := crypto.HexToECDSA(privateKeyHex)
publicKeyCrypto := privateKey.Public()
publicKey, _ := publicKey.(*ecdsa.publicKeyCrypto)

client, err = ethclient.Dial(providerURL)
if err != nil {
    log.Fatal(err)
}

// signedTxs is an array of signed transactions objects
// signedTxs []*types.Transaction
txs := []string{}
for _, tx := range signedTxs {
    data, err := tx.MarshalBinary()
    if err != nil {
        log.Fatal(err)
    }
    txs = append(txs, hexutil.Encode(data))
}

block, err := client.HeaderByNumber(context.Background(), nil)
if err != nil {
    log.Fatal(err)
}

fb := flashbots.NewProvider(signingKey, privateKey, flashbots.DefaultRelayURL)
for i := int64(0); i < attempts; i++ {
    targetBlockNumber := new(big.Int).Add(block.Number, big.NewInt(int64(i)))
    _, err := fb.SendBundle(txs, targetBlockNumber, &flashbots.Options{})
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("submitted for block: %d\n", targetBlockNumber)
}
```
