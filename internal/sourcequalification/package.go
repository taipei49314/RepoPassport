package sourcequalification

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"strconv"
)

const qualificationPackageDomain = "repopass.source-qualification.package.v1"

var qualificationPackageNames = []string{
	"repopass-source.tar",
	"source-archive-manifest-v1.json",
	"source-qualification-linux-amd64-v1.json",
	"source-qualification-windows-amd64-v1.json",
}

func qualificationPackageFilenames() []string {
	return append([]string(nil), qualificationPackageNames...)
}

func qualificationPackageDigest(archive, manifest, linuxReceipt, windowsReceipt []byte) string {
	files := [][]byte{archive, manifest, linuxReceipt, windowsReceipt}
	digest := sha256.New()
	writePackageDigestBytes(digest, []byte(qualificationPackageDomain))
	writePackageDigestBytes(digest, []byte{0})
	for index, data := range files {
		fileDigest := sha256.Sum256(data)
		writePackageDigestBytes(digest, []byte(qualificationPackageNames[index]))
		writePackageDigestBytes(digest, []byte{0})
		writePackageDigestBytes(digest, []byte(strconv.Itoa(len(data))))
		writePackageDigestBytes(digest, []byte{0})
		encoded := make([]byte, hex.EncodedLen(len(fileDigest)))
		hex.Encode(encoded, fileDigest[:])
		writePackageDigestBytes(digest, encoded)
		writePackageDigestBytes(digest, []byte{'\n'})
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func writePackageDigestBytes(destination hash.Hash, value []byte) {
	_, _ = destination.Write(value)
}
