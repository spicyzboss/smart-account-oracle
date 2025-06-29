# Smart Account Oracle: Safe Account Abstraction Vanity

## Requirements

- [rust](https://rust-lang.org)
- [foundry](https://getfoundry.sh)
- an excellent luck for save computation resources.

## Usage

### Generate initializer

```bash
cast calldata "setup(address[],uint256,address,bytes,address,address,uint256,address)" \
  "[<address>]" \
  "1" \
  "0xBD89A1CE4DDe368FFAB0eC35506eEcE0b1fFdc54" \
  "0xfe51f64300000000000000000000000029fcb43b46531bca003ddc8fcb67ffe91900c762" \
  "0xfd0732Dc9E303f09fCEf3a7388Ad10A83459Ec99" \
  "0x0000000000000000000000000000000000000000" \
  "0" \
  "0x5afe7A11E7000000000000000000000000000000" > /tmp/initializer.txt
```

### Running salt generation

```bash
cargo run --bin safe-fortune -- \
  --initializer $(cat /tmp/initializer.txt) \
  --pattern 0000 \
  --mode starts-with
```

### Create SafeProxy from SafeProxyFactory

try calling to `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67` (SafeProxyFactory), then send write operation to this signature `createProxyWithNonce(address,bytes,uint256)(address)` with parameter `0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67` (singleton), `$(cat /tmp/initializer.txt)` (initializer params), and `salt_nonce` from generation step. the vanity smart account should deployed to blockchain.

example foundry send params (not working right now)

```bash
RPC_URL="<enter_your_rpc_url>" \
SAFE_PROXY_FACTORY_ADDRESS="0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67" \
SINGLETON_ADDRESS="0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67" \
cast send -i $SAFE_PROXY_FACTORY_ADDRESS \
"createProxyWithNonce(address,bytes,uint256)(address)" \
$SINGLETON_ADDRESS \
$(cat /tmp/initializer.txt) \
"<salt_nonce>" \
--rpc-url $RPC_URL
```
