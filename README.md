# BackupOperatorToDA

Ported to Ziglang for fun and no profit (all the old + an attempt to enable privs.).

## Get and Build the Thing

```bash
git clone git@github.com:ArchiMoebius/BackupOperatorToDA.git --recurse-submodules

# - OR -

git clone https://github.com/ArchiMoebius/BackupOperatorToDA.git --recurse-submodules
```

### Setup Zig

#### WebInstall

Visit [webinstall](https://webinstall.dev/zig/) or just

```bash
curl -sS https://webi.sh/zig | sh
source ~/.config/envman/PATH.env
```

The above Creates `~/.local/opt/zig`

#### Download Ziglang

Visit [Zig](https://ziglang.org/download/) and download / extract the most recent tagged version.


### Build

```bash
make
tree zig-out
```
