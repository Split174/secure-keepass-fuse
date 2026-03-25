# secure-keepass-fuse

**Disclaimer**: I am not a security engineer. This tool is designed to protect sensitive files (like `age` keys, `kubeconfig`, or SSH keys) from unauthorized background processes by introducing an interactive, human-in-the-loop verification layer.

`secure-keepass-fuse` mounts your KeePass database attachments as a virtual FUSE filesystem. Access to each file is controlled dynamically via interactive prompts.

## How it works

1. **Extraction**: The utility scans your KeePass database at startup and extracts all binary attachments into an in-memory tree.
2. **Mount**: A FUSE filesystem is created at the specified mount point. All files are `ro` (read-only) and only accessible by your current user (mode `0400`).
3. **Dynamic Access Control**: Whenever a process attempts to `open` a file, the driver:
    1. Identifies the process (PID) and its absolute executable path via `/proc/<PID>/exe`.
    2. Checks a local memory cache to see if you have already approved this process.
    3. If no cached decision exists, it triggers a **Zenity** dialog asking for your explicit permission.
    4. Caches your decision based on the `--cache-time` setting.
4. **Enforcement**: If you deny the request, or if the process signature changes, the kernel returns `EACCES` (Permission Denied).

## Requirements

* **Linux** with FUSE support.
* **Zenity**: Required for the interactive GUI authorization prompts.

## Usage

## Install

### Binary Release (Direct)
You can download the pre-compiled binary for your architecture from the [Releases page](https://github.com/Split174/secure-keepass-fuse/releases).

```bash
curl -L -O https://github.com/Split174/secure-keepass-fuse/releases/download/v0.0.3/secure-keepass-fuse-amd64
chmod +x secure-keepass-fuse-amd64
sudo mv secure-keepass-fuse-amd64 /usr/local/bin/secure-keepass-fuse
```

### Arch Linux (AUR)
If you are using Arch Linux or its derivatives (Manjaro, EndeavourOS), you can install the package directly from the AUR using your favorite helper:

```bash
yay -S secure-keepass-fuse-bin
```

### Building from Source
If you prefer to build it yourself, ensure you have `go` installed:

```bash
git clone https://github.com/Split174/secure-keepass-fuse.git
cd secure-keepass-fuse
go build -o secure-keepass-fuse .
sudo cp secure-keepass-fuse /usr/local/bin/
```

### Running
```bash
./secure-keepass-fuse [flags] ./path/to/database.kdbx ./mount/path
```

#### Flags
* `--flat`: All attachments are extracted directly into the root folder, ignoring the original KeePass folder structure.
* `--cache-time <duration>`: How long to remember your access decision (default: `15m`). Examples: `5m`, `1h`, `30s`.
* `--verbose`: Enable detailed logging of access attempts and cache hits/misses.

## Warnings
* **GUI dependency**: Because this tool relies on **Zenity**, it must be run within an active graphical desktop session. It will hang if run in a headless environment (like an SSH session without X11 forwarding) as it will be waiting for a dialog that cannot appear.
* **Memory**: The tool uses `mlockall` to attempt to keep secrets out of swap, but this is a "best-effort" protection.