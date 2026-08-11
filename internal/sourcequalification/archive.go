package sourcequalification

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
)

const (
	archiveBlockSize     = int64(512)
	archiveTrailerSize   = int64(2 * archiveBlockSize)
	maxArchiveFiles      = 16_384
	maxArchiveFileBytes  = int64(128 << 20)
	maxArchiveBytes      = int64(512 << 20)
	maxPortablePathBytes = 255
)

// archiveFile is the exact input needed to reproduce one source archive member
// and its corresponding Git tree entry. Data always contains Git blob bytes,
// never bytes read through working-tree filters.
type archiveFile struct {
	Path    string
	GitMode string
	Data    []byte
}

func validatePortablePath(path string) error {
	if len(path) == 0 || len(path) > maxPortablePathBytes {
		return errors.New("source path length is outside the portable profile")
	}

	segmentStart := 0
	for index := 0; index <= len(path); index++ {
		if index < len(path) && path[index] != '/' {
			value := path[index]
			if value < 0x20 || value > 0x7e {
				return errors.New("source path contains a non-ASCII byte")
			}
			switch value {
			case '\\', ':', '*', '?', '"', '<', '>', '|':
				return errors.New("source path contains a forbidden byte")
			}
			continue
		}

		segment := path[segmentStart:index]
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("source path contains an invalid segment")
		}
		if segment[len(segment)-1] == '.' || segment[len(segment)-1] == ' ' {
			return errors.New("source path segment has a forbidden suffix")
		}
		if windowsReservedDeviceSegment(segment) {
			return errors.New("source path contains a reserved device segment")
		}
		segmentStart = index + 1
	}

	return nil
}

func windowsReservedDeviceSegment(segment string) bool {
	base := segment
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		base = base[:dot]
	}
	base = asciiUpper(base)
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$":
		return true
	}
	if len(base) != 4 || (base[:3] != "COM" && base[:3] != "LPT") {
		return false
	}
	return base[3] >= '1' && base[3] <= '9'
}

func asciiUpper(value string) string {
	result := []byte(value)
	for index, current := range result {
		if current >= 'a' && current <= 'z' {
			result[index] = current - ('a' - 'A')
		}
	}
	return string(result)
}

func asciiFold(value string) string {
	result := []byte(value)
	for index, current := range result {
		if current >= 'A' && current <= 'Z' {
			result[index] = current + ('a' - 'A')
		}
	}
	return string(result)
}

func splitUSTARPath(path string) (string, string, error) {
	if err := validatePortablePath(path); err != nil {
		return "", "", err
	}
	if len(path) <= 100 {
		return "", path, nil
	}
	for index := len(path) - 1; index >= 0; index-- {
		if path[index] != '/' {
			continue
		}
		prefixLength := index
		nameLength := len(path) - index - 1
		if prefixLength >= 1 && prefixLength <= 155 && nameLength >= 1 && nameLength <= 100 {
			return path[:index], path[index+1:], nil
		}
	}
	return "", "", errors.New("source path cannot be represented by canonical USTAR")
}

func canonicalArchiveSize(fileSizes []int64) (int64, error) {
	if len(fileSizes) > maxArchiveFiles {
		return 0, errors.New("source archive contains too many files")
	}

	total := archiveTrailerSize
	for _, size := range fileSizes {
		if size < 0 || size > maxArchiveFileBytes {
			return 0, errors.New("source archive file size is outside the bounded profile")
		}
		padded := size
		if remainder := size % archiveBlockSize; remainder != 0 {
			padded += archiveBlockSize - remainder
		}
		recordSize := archiveBlockSize + padded
		if recordSize > maxArchiveBytes-total {
			return 0, errors.New("source archive exceeds the total size limit")
		}
		total += recordSize
	}
	return total, nil
}

func normalizeArchiveFiles(files []archiveFile) ([]archiveFile, int64, error) {
	if len(files) > maxArchiveFiles {
		return nil, 0, errors.New("source archive contains too many files")
	}

	ordered := append([]archiveFile(nil), files...)
	sizes := make([]int64, len(ordered))
	paths := make(map[string]struct{}, len(ordered))
	foldedPaths := make(map[string]struct{}, len(ordered))
	for index, file := range ordered {
		if err := validatePortablePath(file.Path); err != nil {
			return nil, 0, err
		}
		if _, _, err := splitUSTARPath(file.Path); err != nil {
			return nil, 0, err
		}
		if file.GitMode != "100644" && file.GitMode != "100755" {
			return nil, 0, errors.New("source archive contains an unsupported Git mode")
		}
		if _, exists := paths[file.Path]; exists {
			return nil, 0, errors.New("source archive contains a duplicate path")
		}
		paths[file.Path] = struct{}{}
		folded := asciiFold(file.Path)
		if _, exists := foldedPaths[folded]; exists {
			return nil, 0, errors.New("source archive contains an ASCII case-fold collision")
		}
		foldedPaths[folded] = struct{}{}
		sizes[index] = int64(len(file.Data))
	}

	for path := range paths {
		for index := strings.IndexByte(path, '/'); index >= 0; {
			if _, exists := paths[path[:index]]; exists {
				return nil, 0, errors.New("source archive contains a file-directory collision")
			}
			next := strings.IndexByte(path[index+1:], '/')
			if next < 0 {
				break
			}
			index += next + 1
		}
	}

	total, err := canonicalArchiveSize(sizes)
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].Path < ordered[right].Path
	})
	return ordered, total, nil
}

func buildCanonicalArchive(files []archiveFile) ([]byte, error) {
	ordered, total, err := normalizeArchiveFiles(files)
	if err != nil {
		return nil, err
	}
	if uint64(total) > uint64(^uint(0)>>1) {
		return nil, errors.New("source archive is too large for this platform")
	}

	archive := make([]byte, 0, int(total))
	var zeroBlock [512]byte
	for _, file := range ordered {
		header, err := canonicalUSTARHeader(file.Path, file.GitMode, int64(len(file.Data)))
		if err != nil {
			return nil, err
		}
		archive = append(archive, header[:]...)
		archive = append(archive, file.Data...)
		padding := (int(archiveBlockSize) - len(file.Data)%int(archiveBlockSize)) % int(archiveBlockSize)
		archive = append(archive, zeroBlock[:padding]...)
	}
	archive = append(archive, zeroBlock[:]...)
	archive = append(archive, zeroBlock[:]...)
	if int64(len(archive)) != total {
		return nil, errors.New("source archive size calculation mismatch")
	}
	return archive, nil
}

func canonicalUSTARHeader(path, gitMode string, size int64) ([512]byte, error) {
	var header [512]byte
	prefix, name, err := splitUSTARPath(path)
	if err != nil {
		return header, err
	}
	if size < 0 || size > maxArchiveFileBytes {
		return header, errors.New("source archive file size is outside the bounded profile")
	}

	copy(header[0:100], name)
	switch gitMode {
	case "100644":
		copy(header[100:108], "0000644\x00")
	case "100755":
		copy(header[100:108], "0000755\x00")
	default:
		return header, errors.New("source archive contains an unsupported Git mode")
	}
	copy(header[108:116], "0000000\x00")
	copy(header[116:124], "0000000\x00")
	if err := writeOctalNUL(header[124:136], size); err != nil {
		return header, err
	}
	copy(header[136:148], "00000000000\x00")
	copy(header[148:156], "        ")
	header[156] = '0'
	copy(header[257:263], "ustar\x00")
	copy(header[263:265], "00")
	copy(header[329:337], "0000000\x00")
	copy(header[337:345], "0000000\x00")
	copy(header[345:500], prefix)

	checksum := int64(0)
	for _, value := range header {
		checksum += int64(value)
	}
	if err := writeUSTARChecksum(header[148:156], checksum); err != nil {
		return header, err
	}
	return header, nil
}

func writeOctalNUL(field []byte, value int64) error {
	if value < 0 || len(field) < 2 {
		return errors.New("invalid canonical octal field")
	}
	digits := len(field) - 1
	encoded := strconv.FormatInt(value, 8)
	if len(encoded) > digits {
		return errors.New("canonical octal value does not fit")
	}
	for index := 0; index < digits; index++ {
		field[index] = '0'
	}
	copy(field[digits-len(encoded):digits], encoded)
	field[digits] = 0
	return nil
}

func writeUSTARChecksum(field []byte, value int64) error {
	if value < 0 || len(field) != 8 {
		return errors.New("invalid canonical USTAR checksum")
	}
	encoded := strconv.FormatInt(value, 8)
	if len(encoded) > 6 {
		return errors.New("canonical USTAR checksum does not fit")
	}
	for index := 0; index < 6; index++ {
		field[index] = '0'
	}
	copy(field[6-len(encoded):6], encoded)
	field[6] = 0
	field[7] = ' '
	return nil
}

func verifyCanonicalArchive(archive []byte, files []archiveFile, expectedTreeSHA1 string) error {
	if int64(len(archive)) > maxArchiveBytes {
		return errors.New("source archive exceeds the total size limit")
	}
	if !validGitSHA1(expectedTreeSHA1) {
		return errors.New("expected Git tree ID is invalid")
	}
	ordered, total, err := normalizeArchiveFiles(files)
	if err != nil {
		return err
	}
	if int64(len(archive)) != total {
		return errors.New("source archive has a noncanonical length")
	}
	reconstructed, err := reconstructGitTreeSHA1(ordered)
	if err != nil {
		return err
	}
	if reconstructed != expectedTreeSHA1 {
		return errors.New("source archive Git tree does not match the expected tree")
	}

	offset := 0
	for _, file := range ordered {
		header, err := canonicalUSTARHeader(file.Path, file.GitMode, int64(len(file.Data)))
		if err != nil {
			return err
		}
		if offset > len(archive)-len(header) || !bytes.Equal(archive[offset:offset+len(header)], header[:]) {
			return errors.New("source archive contains a noncanonical USTAR header")
		}
		offset += len(header)
		if len(file.Data) > len(archive)-offset || !bytes.Equal(archive[offset:offset+len(file.Data)], file.Data) {
			return errors.New("source archive member bytes do not match")
		}
		offset += len(file.Data)
		padding := (int(archiveBlockSize) - len(file.Data)%int(archiveBlockSize)) % int(archiveBlockSize)
		if padding > len(archive)-offset || !zeroBytes(archive[offset:offset+padding]) {
			return errors.New("source archive contains noncanonical member padding")
		}
		offset += padding
	}
	if len(archive)-offset != int(archiveTrailerSize) || !zeroBytes(archive[offset:]) {
		return errors.New("source archive has a noncanonical terminator")
	}
	return nil
}

func zeroBytes(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func validGitSHA1(value string) bool {
	if len(value) != sha1.Size*2 {
		return false
	}
	for index := 0; index < len(value); index++ {
		current := value[index]
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}

func gitBlobSHA1(data []byte) string {
	objectID := gitObjectSHA1("blob", data)
	return hex.EncodeToString(objectID[:])
}

type gitTreeNode struct {
	files       map[string]gitTreeFile
	directories map[string]*gitTreeNode
}

type gitTreeFile struct {
	mode     string
	objectID [sha1.Size]byte
}

type gitTreeChild struct {
	name     string
	mode     string
	sortKey  string
	objectID [sha1.Size]byte
}

func newGitTreeNode() *gitTreeNode {
	return &gitTreeNode{
		files:       make(map[string]gitTreeFile),
		directories: make(map[string]*gitTreeNode),
	}
}

func reconstructGitTreeSHA1(files []archiveFile) (string, error) {
	ordered, _, err := normalizeArchiveFiles(files)
	if err != nil {
		return "", err
	}
	root := newGitTreeNode()
	for _, file := range ordered {
		segments := strings.Split(file.Path, "/")
		node := root
		for _, segment := range segments[:len(segments)-1] {
			if _, exists := node.files[segment]; exists {
				return "", errors.New("source archive contains a file-directory collision")
			}
			next, exists := node.directories[segment]
			if !exists {
				next = newGitTreeNode()
				node.directories[segment] = next
			}
			node = next
		}
		name := segments[len(segments)-1]
		if _, exists := node.directories[name]; exists {
			return "", errors.New("source archive contains a file-directory collision")
		}
		if _, exists := node.files[name]; exists {
			return "", errors.New("source archive contains a duplicate path")
		}
		node.files[name] = gitTreeFile{
			mode:     file.GitMode,
			objectID: gitObjectSHA1("blob", file.Data),
		}
	}

	rootID, err := root.objectID()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(rootID[:]), nil
}

func (node *gitTreeNode) objectID() ([sha1.Size]byte, error) {
	children := make([]gitTreeChild, 0, len(node.files)+len(node.directories))
	for name, file := range node.files {
		children = append(children, gitTreeChild{
			name: name, mode: file.mode, sortKey: name + "\x00", objectID: file.objectID,
		})
	}
	for name, directory := range node.directories {
		objectID, err := directory.objectID()
		if err != nil {
			return [sha1.Size]byte{}, err
		}
		children = append(children, gitTreeChild{
			name: name, mode: "40000", sortKey: name + "/", objectID: objectID,
		})
	}
	sort.Slice(children, func(left, right int) bool {
		return children[left].sortKey < children[right].sortKey
	})

	payloadSize := 0
	for _, child := range children {
		recordSize := len(child.mode) + 1 + len(child.name) + 1 + sha1.Size
		if recordSize > int(maxArchiveBytes)-payloadSize {
			return [sha1.Size]byte{}, errors.New("Git tree payload exceeds the bounded profile")
		}
		payloadSize += recordSize
	}
	payload := make([]byte, 0, payloadSize)
	for _, child := range children {
		payload = append(payload, child.mode...)
		payload = append(payload, ' ')
		payload = append(payload, child.name...)
		payload = append(payload, 0)
		payload = append(payload, child.objectID[:]...)
	}
	return gitObjectSHA1("tree", payload), nil
}

// gitObjectSHA1 reproduces Git's object identity format. SHA-1 is required by
// RFC-0002 for Git compatibility; archive and manifest integrity use SHA-256.
func gitObjectSHA1(kind string, data []byte) [sha1.Size]byte {
	hash := sha1.New() // #nosec G505 -- this is a Git object identifier, not a security digest.
	hash.Write([]byte(kind))
	hash.Write([]byte{' '})
	hash.Write([]byte(strconv.FormatInt(int64(len(data)), 10)))
	hash.Write([]byte{0})
	hash.Write(data)
	var result [sha1.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}
