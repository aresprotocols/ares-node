# ares-node

## Start with docker
* images name: paritytech/ci-linux:974ba3ac-20201006
* docker run --rm -v $(PWD):/builds paritytech/ci-linux:3d4ca6a9-20210708 bash -c "cargo build --release"

## Make chain spec json
* Make human readable json
```
./target/release/<YOUR_APP> build-spec --chain staging --disable-default-bootnode > my-staging.json

```
* Make raw json
```
./target/release/<YOUR_APP> build-spec --chain staging --raw  --disable-default-bootnode > my-staging-raw.json
```

## Generate a node key for your chain, can be generate with command
```
./target/release/<YOUR_APP> key generate-node-key
```

* The sample of the return value, yours will be different.
```
12D3KooWGuNM14pnggJogJSUtJ8u1Quw9CuqwR6j5dr9SbFF57kP
62c32b50d59b5a1b3ef71789be121dd636040a403495335c7a44ccd1824f0f1d%  
```

## Start bootnodes

* To test, you can run the following command to clear the chain data directory.
```
rm -rf /tmp/bootnode1 /tmp/validator*
```
### Start boot node
```
./target/debug/substrate \
    --ws-external \
    --rpc-external \
    --rpc-cors=all \
    --rpc-methods=Unsafe \
    --node-key 62c32b50d59b5a1b3ef71789be121dd636040a403495335c7a44ccd1824f0f1d \
    --base-path /tmp/bootnode1 \
    --chain my-staging-raw.json \
    --name bootnode1
    --validator 
```

### Start no less than 3 validator nodes
```
# Example, note that the port, ws-port and rpc-port are different on each node.
./target/debug/substrate \
    --base-path  /tmp/validator1 \
    --chain my-staging-raw.json \
    --bootnodes  /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWGuNM14pnggJogJSUtJ8u1Quw9CuqwR6j5dr9SbFF57kP \
    --port 30336 \
    --ws-port 9947 \
    --rpc-port 9936 \
    --name  validator1 \
    --validator 
```
* After successful startup, 1 peer is displayed. Repeat the above operation to start multiple verifier nodes.

### Set session key for each node
* Curl direct submission is recommended
```curl
curl http://<YOUR_IP>:<RPC_PORT>  -H "Content-Type:application/json;charset=utf-8" -d "@FILENAME"
```

* Babe session file content example 
```json
{
    "jsonrpc":"2.0",
    "id":1,
    "method":"author_insertKey",
    "params": [
        "babe",
        "blur pioneer frown science banana impose avoid law act strategy have bronze//1//babe",
        "0x1e876fa1b4bbb82785ea5670b7ce0976beaf7536b6a0cc05deba7a54ab709421"
    ]
}
```

* Grandpa session file content example
```json
{
    "jsonrpc":"2.0",
    "id":1,
    "method":"author_insertKey",
    "params": [
        "babe",
        "blur pioneer frown science banana impose avoid law act strategy have bronze//1//babe",
        "0x1e876fa1b4bbb82785ea5670b7ce0976beaf7536b6a0cc05deba7a54ab709421"
    ]
}
```

* Imonline session file content example
```json
{
    "jsonrpc":"2.0",
    "id":1,
    "method":"author_insertKey",
    "params": [
        "imon",
        "blur pioneer frown science banana impose avoid law act strategy have bronze//1//im_online",
        "0x94ff4a3dcd40926a375e9ebd640972598f7cf372e745fc5727a8020864bcb850"
    ]
}

```
