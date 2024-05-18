# A small set of utilities ported to Ziglang (for fun and no profit)

## Contents

### BackupOperatorToDomainAdministrator.zig

As the name implies - with the right group / privileges - "there be dragons".

```powershell
# Dump workgroup box
.\BackupOperatorToDomainAdministrator.exe HOSTNAME/user:password@HOSTNAME \\HOSTNAME\share\

# Dump domain box
.\BackupOperatorToDomainAdministrator.exe DOMAIN/user:password@ip \\HOSTNAME\share\
```

### ModifyPrivilege.zig

Modify a processes privileges (enable/disable/remove)

```powershell
# Enable all privileges to the current terminal
.\ModifyPrivilege.exe 0

# Enable all privilges on this PID
.\ModifyPrivilege.exe <some pid>
```

### HighToSystem.zig

Provided a process in a 'high' context - leverage that to obtain `SYSTEM`.

```
.\HighToSystem.exe <pid> <fullpath to an executable>
```

### Shortcut.zig

Provided a quick utility to create shortcuts from the command line.

```
 .\Shortcut.exe  C:\windows\system32\cmd.exe C:\users\username\desktop\cmd.lnk C:\
```

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
