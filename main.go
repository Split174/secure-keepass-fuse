package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/tobischo/gokeepasslib/v3"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Global config flags
var (
	verbose   bool
	cacheTime time.Duration
	flatMode  bool
)

// --- Cache Structures ---

type cacheEntry struct {
	allowed bool
	expires time.Time
}

var (
	accessCache = make(map[string]cacheEntry)
	cacheMutex  sync.RWMutex
)

// --- Domain Structures ---

// SecuredFile represents the content for a specific extracted file.
type SecuredFile struct {
	Name    string
	Content []byte
}

// DirEntry represents a directory in the in-memory tree using a recursive structure.
type DirEntry struct {
	Name  string
	Files map[string]*SecuredFile
	Dirs  map[string]*DirEntry
}

// NewDirEntry creates a new directory entry structure
func NewDirEntry(name string) *DirEntry {
	return &DirEntry{
		Name:  name,
		Files: make(map[string]*SecuredFile),
		Dirs:  make(map[string]*DirEntry),
	}
}

// --- Logic ---

// wipeBytes zeroes out the byte slice
func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// sanitizeName replaces file system path separators with underscores
func sanitizeName(name string) string {
	return strings.ReplaceAll(name, "/", "_")
}

func isDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

// loadDB loads the KDBX file using gokeepasslib and builds the in-memory definition tree.
func loadDB(dbPath, keyFile string, pwd []byte) (*DirEntry, error) {
	log.Println("[INFO] Opening database...")

	file, err := os.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open db file: %w", err)
	}
	defer file.Close()

	var creds *gokeepasslib.DBCredentials
	pwdStr := string(pwd)

	if keyFile != "" {
		creds, err = gokeepasslib.NewPasswordAndKeyCredentials(pwdStr, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load credentials with keyfile: %w", err)
		}
	} else {
		creds = gokeepasslib.NewPasswordCredentials(pwdStr)
	}

	db := gokeepasslib.NewDatabase()
	db.Credentials = creds

	if err := gokeepasslib.NewDecoder(file).Decode(db); err != nil {
		return nil, fmt.Errorf("failed to decode kdbx: %w", err)
	}

	if err := db.UnlockProtectedEntries(); err != nil {
		return nil, fmt.Errorf("failed to unlock entries: %w", err)
	}

	log.Println("[INFO] Database decrypted. Building file tree (extracting all attachments)...")

	rootEntry := NewDirEntry("root")

	var processGroup func(g gokeepasslib.Group, parentDir *DirEntry)
	processGroup = func(g gokeepasslib.Group, parentDir *DirEntry) {
		groupName := sanitizeName(g.Name)
		if groupName == "" {
			groupName = "_unnamed_group_"
		}

		var targetDir *DirEntry

		if flatMode {
			targetDir = rootEntry
		} else {
			currentDir, exists := parentDir.Dirs[groupName]
			if !exists {
				currentDir = NewDirEntry(groupName)
				parentDir.Dirs[groupName] = currentDir
			}
			targetDir = currentDir
		}

		for _, entry := range g.Entries {
			title := entry.GetTitle()

			if len(entry.Binaries) == 0 {
				continue
			}

			for _, binRef := range entry.Binaries {
				fName := strings.TrimSpace(binRef.Name)

				if fName == "KeeAgent.settings" {
					if verbose {
						log.Printf("   [SKIP] Ignoring '%s' in entry '%s'", fName, title)
					}
					continue
				}

				safeFName := sanitizeName(fName)

				binaryData := db.FindBinary(binRef.Value.ID)
				if binaryData == nil {
					log.Printf("   [WARN] Binary '%s' referenced in entry '%s' not found in DB store.", fName, title)
					continue
				}

				content, err := binaryData.GetContentBytes()
				if err != nil {
					log.Printf("   [ERR] Failed to get content bytes for '%s': %v", fName, err)
					continue
				}

				if len(content) == 0 {
					log.Printf("   [WARN] File '%s' in entry '%s' is empty.", fName, title)
				}

				finalFName := safeFName
				counter := 1
				ext := filepath.Ext(safeFName)
				nameWithoutExt := strings.TrimSuffix(safeFName, ext)

				for {
					if _, exists := targetDir.Files[finalFName]; !exists {
						break
					}
					finalFName = fmt.Sprintf("%s_%d%s", nameWithoutExt, counter, ext)
					counter++
				}

				log.Printf("[EXTRACT] Extracted '%s' from entry '%s' -> '%s' (%d bytes)", fName, title, finalFName, len(content))

				targetDir.Files[finalFName] = &SecuredFile{
					Name:    finalFName,
					Content: content,
				}
			}
		}

		for _, sub := range g.Groups {
			processGroup(sub, targetDir)
		}
	}

	for _, g := range db.Content.Root.Groups {
		processGroup(g, rootEntry)
	}

	return rootEntry, nil
}

// askUserAccess summons a zenity dialog asking user permission
func askUserAccess(exePath string, pid uint32, fileName string) bool {
	title := "Request for access to a secret file"
	text := fmt.Sprintf(
		"The process requests access to a file:\n\n"+
			"<b>File:</b> %s\n"+
			"<b>Process:</b> %s\n"+
			"<b>PID:</b> %d\n\n"+
			"Allow access?", fileName, exePath, pid,
	)

	cmd := exec.Command("zenity", "--question",
		"--title", title,
		"--text", text,
		"--width=450",
	)

	err := cmd.Run()
	return err == nil
}

// --- FUSE Operations ---

type SecureDirNode struct {
	fs.Inode
	Entry *DirEntry
}

var _ fs.NodeOnAdder = (*SecureDirNode)(nil)

func (n *SecureDirNode) OnAdd(ctx context.Context) {
	for name, dirEntry := range n.Entry.Dirs {
		childNode := &SecureDirNode{Entry: dirEntry}
		childInode := n.NewPersistentInode(ctx, childNode, fs.StableAttr{Mode: fuse.S_IFDIR})
		n.AddChild(name, childInode, true)
	}

	for name, fileData := range n.Entry.Files {
		childNode := &SecureFileNode{Data: fileData}
		childInode := n.NewPersistentInode(ctx, childNode, fs.StableAttr{Mode: fuse.S_IFREG})
		n.AddChild(name, childInode, true)
	}
}

type SecureFileNode struct {
	fs.Inode
	Data *SecuredFile
}

var _ fs.NodeOpener = (*SecureFileNode)(nil)
var _ fs.NodeReader = (*SecureFileNode)(nil)
var _ fs.NodeGetattrer = (*SecureFileNode)(nil)

func (n *SecureFileNode) Getattr(ctx context.Context, fh fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Size = uint64(len(n.Data.Content))
	out.Mode = 0400 // Read-only for owner
	out.Owner.Uid = uint32(os.Getuid())
	out.Owner.Gid = uint32(os.Getgid())
	return 0
}

func (n *SecureFileNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	caller, ok := fuse.FromContext(ctx)
	if !ok {
		return nil, 0, syscall.EACCES
	}

	pid := caller.Pid
	procPath := fmt.Sprintf("/proc/%d/exe", pid)

	realPath, err := os.Readlink(procPath)
	if err != nil {
		log.Printf("[DENY] Error reading executable path for PID %d: %v", pid, err)
		return nil, 0, syscall.EACCES
	}
	realPath = strings.TrimSuffix(realPath, " (deleted)")

	cacheKey := realPath + "|" + n.Data.Name

	cacheMutex.RLock()
	entry, exists := accessCache[cacheKey]
	cacheMutex.RUnlock()

	now := time.Now()
	if exists && now.Before(entry.expires) {
		if entry.allowed {
			if verbose {
				log.Printf("[CACHE-ALLOW] Process '%s' allowed to '%s'", realPath, n.Data.Name)
			}
			return nil, 0, 0
		}
		if verbose {
			log.Printf("[CACHE-DENY] Process '%s' denied to '%s'", realPath, n.Data.Name)
		}
		return nil, 0, syscall.EACCES
	}

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	entry, exists = accessCache[cacheKey]
	if exists && time.Now().Before(entry.expires) {
		if entry.allowed {
			return nil, 0, 0
		}
		return nil, 0, syscall.EACCES
	}

	allowed := askUserAccess(realPath, pid, n.Data.Name)

	accessCache[cacheKey] = cacheEntry{
		allowed: allowed,
		expires: time.Now().Add(cacheTime),
	}

	if allowed {
		log.Printf("[ZENITY-ALLOW] User granted access: %s -> %s", realPath, n.Data.Name)
		return nil, 0, 0
	}

	log.Printf("[ZENITY-DENY] User denied access: %s -> %s", realPath, n.Data.Name)
	return nil, 0, syscall.EACCES
}

func (n *SecureFileNode) Read(ctx context.Context, fh fs.FileHandle, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	end := int(off) + len(dest)
	if end > len(n.Data.Content) {
		end = len(n.Data.Content)
	}
	if int(off) < len(n.Data.Content) {
		copy(dest, n.Data.Content[off:end])
		return fuse.ReadResultData(dest[:end-int(off)]), 0
	}
	return fuse.ReadResultData(nil), 0
}

func main() {
	keyFilePtr := flag.String("keyfile", "", "Path to keyfile")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging for allowed access")
	flag.BoolVar(&flatMode, "flat", false, "Extract all files directly into the mountpoint ignoring DB folders")
	flag.DurationVar(&cacheTime, "cache-time", 15*time.Minute, "Time to remember user access decision (e.g., 5m, 1h)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("Usage: secure-mount [options] <db.kdbx> <mountpoint>")
		flag.PrintDefaults()
		os.Exit(1)
	}
	dbPath := args[0]
	mountPoint := args[1]

	stat, err := os.Stat(mountPoint)
	if err != nil {
		if os.IsNotExist(err) {
			if mkdirErr := os.MkdirAll(mountPoint, 0700); mkdirErr != nil {
				log.Fatalf("[FATAL] Failed to create mountpoint: %v", mkdirErr)
			}
		} else {
			log.Fatalf("[FATAL] Error checking mountpoint: %v", err)
		}
	} else {
		if !stat.IsDir() {
			log.Fatalf("[FATAL] Mountpoint %s is a file, not a directory.", mountPoint)
		}
		empty, err := isDirEmpty(mountPoint)
		if err != nil {
			log.Fatalf("[FATAL] Failed to check if mountpoint is empty: %v", err)
		}
		if !empty {
			log.Fatalf("[FATAL] SAFETY ABORT: Mount point '%s' is NOT empty. Mounting here would hide existing files!", mountPoint)
		}
	}

	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		log.Printf("[WARN] Failed to lock memory (mlockall): %v. Secrets might swap to disk.", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	userCancelCh := make(chan struct{})
	go func() {
		<-sigCh
		log.Println("Interrupt received, shutting down...")
		os.Stdin.Close()
		close(userCancelCh)
	}()

	fmt.Print("KeePass Password: ")
	bPwd, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		log.Fatal(err)
	}

	select {
	case <-userCancelCh:
		wipeBytes(bPwd)
		os.Exit(0)
	default:
	}

	rootEntry, err := loadDB(dbPath, *keyFilePtr, bPwd)

	wipeBytes(bPwd)
	runtime.GC()

	if err != nil {
		log.Fatalf("Fatal error loading DB: %v", err)
	}

	hasFiles := false
	var checkRec func(*DirEntry)
	checkRec = func(d *DirEntry) {
		if len(d.Files) > 0 {
			hasFiles = true
			return
		}
		for _, sub := range d.Dirs {
			checkRec(sub)
			if hasFiles {
				return
			}
		}
	}
	checkRec(rootEntry)

	if !hasFiles {
		log.Println("[WARN] No files loaded. DB seems to have no attachments.")
	}

	opts := &fs.Options{
		MountOptions: fuse.MountOptions{
			FsName:         "SecureFS",
			Name:           "kpx",
			SingleThreaded: true,
			Options:        []string{"ro", "noexec", "nosuid", "nodev"},
		},
	}

	select {
	case <-userCancelCh:
		os.Exit(0)
	default:
	}

	server, err := fs.Mount(mountPoint, &SecureDirNode{Entry: rootEntry}, opts)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Mounted successfully at %s", mountPoint)
	log.Printf("Flat mode: %v | Cache: %s | Press Ctrl+C to unmount.", flatMode, cacheTime)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Unmounting...")
		server.Unmount()
	}()

	server.Wait()
}
