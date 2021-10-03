
<img src="zokrates_logo.svg" width="100%" height="180">

# ZoKrates

[![Join the chat at https://gitter.im/ZoKrates/Lobby](https://badges.gitter.im/ZoKrates/Lobby.svg)](https://gitter.im/ZoKrates/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![CircleCI develop](https://img.shields.io/circleci/project/github/Zokrates/ZoKrates/develop.svg?label=develop)](https://circleci.com/gh/Zokrates/ZoKrates/tree/develop)

This is a toolbox for zkSNARKs on Bitcoin SV.

_This is a proof-of-concept implementation. It has not been tested for production._

## Getting Started


Alternatively, you can install the ZoKrates CLI:

```bash
cargo build --release
```

Have a look at the [documentation](https://zokrates.github.io/) for more information about using ZoKrates.
[Get started](https://zokrates.github.io/gettingstarted.html), then try a [tutorial](https://zokrates.github.io/examples/rng_tutorial.html)!

## Getting Help

If you run into problems, ZoKrates has a [Slack](https://join.slack.com/t/scryptworkspace/shared_invite/enQtNzQ1OTMyNDk1ODU3LTJmYjE5MGNmNDZhYmYxZWM4ZGY2MTczM2NiNTIxYmFhNTVjNjE5MGYwY2UwNDYxMTQyNGU2NmFkNTY5MmI1MWM) room.

## License

ZoKrates is released under the GNU Lesser General Public License v3.

## Contributing

We happily welcome contributions. You can either pick an existing issue or reach out on [Slack](https://join.slack.com/t/scryptworkspace/shared_invite/enQtNzQ1OTMyNDk1ODU3LTJmYjE5MGNmNDZhYmYxZWM4ZGY2MTczM2NiNTIxYmFhNTVjNjE5MGYwY2UwNDYxMTQyNGU2NmFkNTY5MmI1MWM).

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in the work shall be licensed as above, without any additional terms or conditions.

### Git Hooks

You can enable zokrates git hooks locally by running:

```sh
git config core.hooksPath .githooks
```



### DSL

examples/key_statement_proof.zok

```
import "hashes/sha256/256bitPadded" as sha256
import "utils/pack/u32/unpack128" as unpack128
import "utils/pack/u32/pack128" as pack128
def main(private field[2] preimage, field h0, field h1):

    u32[4] a_bits = unpack128(preimage[0])
    u32[4] b_bits = unpack128(preimage[1])
    u32[8] privkey = [...a_bits, ...b_bits]
    u32[8] res = sha256(privkey)

    assert(h0 == pack128(res[0..4]))
    assert(h1 == pack128(res[4..8]))

    return

```


### Workflow
eg. 

    privateKey: ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5

    publicKey: 0494d6deea102c33307a5ae7e41515198f6fc19d3b11abeca5bff56f1011ed2d8e3d8f02cbd20e8c53d8050d681397775d0dc8b0ad406b261f9b4c94404201cab3

```bash
# compile
./target/release/zokrates compile -i examples/key_statement_proof.zok
# compute witness 
./target/release/zokrates compute-witness -a 314077308411032793321278816725012958289 316495952764820137513325325447450102725 67428615251739275197038733346106089224   232995379825841761673536055030921300908 
# generate a proof of computation
./target/release/zokrates generate-key-proof
# or verify natively
./target/release/zokrates verify-key-proof -p 0494d6deea102c33307a5ae7e41515198f6fc19d3b11abeca5bff56f1011ed2d8e3d8f02cbd20e8c53d8050d681397775d0dc8b0ad406b261f9b4c94404201cab3
```
