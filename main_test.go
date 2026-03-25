package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestWipeBytes(t *testing.T) {
	secret := []byte("super_secret_password")
	wipeBytes(secret)

	for i, b := range secret {
		if b != 0 {
			t.Errorf("Byte at index %d is not 0 (got %d)", i, b)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal.txt", "normal.txt"},
		{"folder/file.json", "folder_file.json"},
		{"a/b/c/d", "a_b_c_d"},
		{"/root_file", "_root_file"},
	}

	for _, tc := range tests {
		actual := sanitizeName(tc.input)
		if actual != tc.expected {
			t.Errorf("sanitizeName(%q) = %q; want %q", tc.input, actual, tc.expected)
		}
	}
}

func TestIsDirEmpty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test_dir_empty_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	empty, err := isDirEmpty(tmpDir)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !empty {
		t.Error("Expected directory to be empty")
	}

	tmpFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(tmpFile, []byte("data"), 0644); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	empty, err = isDirEmpty(tmpDir)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if empty {
		t.Error("Expected directory to NOT be empty")
	}

	// Тест 3: Файл вместо директории (должна быть ошибка)
	_, err = isDirEmpty(tmpFile)
	if err == nil {
		t.Error("Expected error when calling isDirEmpty on a file")
	}
}

func TestNewDirEntry(t *testing.T) {
	name := "my_folder"
	entry := NewDirEntry(name)

	if entry.Name != name {
		t.Errorf("Expected name %q, got %q", name, entry.Name)
	}
	if entry.Files == nil {
		t.Error("Files map should be initialized")
	}
	if entry.Dirs == nil {
		t.Error("Dirs map should be initialized")
	}
}

func TestSecureFileNode_Getattr(t *testing.T) {
	content := []byte("hello world") // 11 bytes
	node := &SecureFileNode{
		Data: &SecuredFile{
			Name:    "test.txt",
			Content: content,
		},
	}

	out := &fuse.AttrOut{}
	errno := node.Getattr(context.Background(), nil, out)

	if errno != 0 {
		t.Errorf("Expected errno 0, got %v", errno)
	}

	if out.Size != 11 {
		t.Errorf("Expected size 11, got %d", out.Size)
	}

	if out.Mode != 0400 {
		t.Errorf("Expected mode 0400, got %o", out.Mode)
	}
}

func TestSecureFileNode_Read(t *testing.T) {
	content := []byte("0123456789") // длина 10
	node := &SecureFileNode{
		Data: &SecuredFile{
			Name:    "data.bin",
			Content: content,
		},
	}

	tests := []struct {
		name     string
		offset   int64
		destSize int
		expected []byte
	}{
		{"Read from start", 0, 5, []byte("01234")},
		{"Read middle", 2, 4, []byte("2345")},
		{"Read past EOF", 8, 10, []byte("89")},
		{"Read far beyond EOF", 20, 5, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dest := make([]byte, tc.destSize)
			res, errno := node.Read(context.Background(), nil, dest, tc.offset)

			if errno != 0 {
				t.Fatalf("Expected errno 0, got %v", errno)
			}

			buf := make([]byte, tc.destSize)
			b, status := res.Bytes(buf)
			if status != 0 {
				t.Fatalf("Expected status 0, got %v", status)
			}

			actualStr := string(b)
			expectedStr := string(tc.expected)

			if actualStr != expectedStr {
				t.Errorf("Expected %q, got %q", expectedStr, actualStr)
			}
		})
	}
}
