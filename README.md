# A small set of utilities ported to Ziglang (for fun and no profit)

## Contents

### BackupOperatorToDomainAdministrator.zig

As the name implies - with the right group / privileges - "there be dragons".

### ModifyPrivilege.zig

Modify a processes privileges (enable/disable/remove)

### HighToSystem.zig

Provided a process in a 'high' context - leverage that to obtain `SYSTEM`.

### Shellcode

An example of shellcode execution on both Windows and Linux (i.e. msfvenom payload).

## Get and Build

```bash
git clone git@github.com:ArchiMoebius/zig-win32-utilities.git --recurse-submodules

# - OR -

git clone https://github.com/ArchiMoebius/zig-win32-utilities.git --recurse-submodules
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

Creates those `*.exe` files.

```bash
make
tree zig-out
```

### Development

Creates those `*.exe` and `*.pdb` files.

```bash
make debug
tree zig-out
```
