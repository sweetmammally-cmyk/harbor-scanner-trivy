package dbmgr

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// checkUpstream is the cheap upstream check of DEMAND section 7.2: it gets the
// remote manifest and compares its digest with InstalledDigest, the manifest
// digest of the DB we have. An empty InstalledDigest (for example the seed DB)
// always counts as changed. It returns the manifest so a download can follow
// without asking again.
func checkUpstream(ctx context.Context, client *registryClient, InstalledDigest string) (ociManifest, string, bool, error) {
	manifest, digest, err := client.getManifest(ctx)
	if err != nil {
		return ociManifest{}, "", false, fmt.Errorf("upstream check: %w", err)
	}
	return manifest, digest, digest != InstalledDigest, nil
}

// downloadDB downloads the DB layer of the manifest from client and extracts
// the files named in wantFiles (for example "trivy.db" and "metadata.json") into
// destDir, which must exist and be empty. Only call it after the source passed
// its pre-check (DEMAND section 7.3).
//
// Two limits apply: ctx carries the overall cap (SCANNER_DB_DOWNLOAD_TIMEOUT),
// and stallTimeout aborts the download when no bytes arrive for that long.
// The layer size and digest are checked after the whole layer is read; on any
// error destDir must not be used.
func downloadDB(ctx context.Context, client *registryClient, layer ociDescriptor, destDir string,
	stallTimeout time.Duration, wantFiles []string) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	// The timer is reset on every read that returns data, see stallReader.
	stall := time.AfterFunc(stallTimeout, func() {
		cancel(fmt.Errorf("download stalled: no data for %s", stallTimeout))
	})
	defer stall.Stop()

	body, err := client.getBlob(ctx, layer.Digest)
	if err != nil {
		return downloadError(ctx, err)
	}
	defer func() { _ = body.Close() }()

	// Read one byte more than expected, so a too large layer is noticed.
	hasher := sha256.New()
	counted := &stallReader{reader: io.LimitReader(body, layer.Size+1), timer: stall, timeout: stallTimeout}
	stream := io.TeeReader(counted, hasher)

	gz, err := gzip.NewReader(stream)
	if err != nil {
		return downloadError(ctx, fmt.Errorf("reading DB layer: %w", err))
	}
	found := map[string]bool{}
	archive := tar.NewReader(gz)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return downloadError(ctx, fmt.Errorf("reading DB layer: %w", err))
		}

		// Only regular files with an expected name at the top level are extracted.
		name := strings.TrimPrefix(header.Name, "./")
		if header.Typeflag != tar.TypeReg || !slices.Contains(wantFiles, name) {
			continue
		}
		file, err := createFile(filepath.Join(destDir, name))
		if err != nil {
			return fmt.Errorf("%w: extracting %s: %w", errLocalDisk, name, err)
		}
		_, err = io.Copy(file, archive)
		if err == nil {
			// Flush to disk before the version can be activated.
			err = file.Sync()
		}
		closeErr := file.Close()
		// File errors (write, sync) are *fs.PathError; reading the layer never returns one.
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			return fmt.Errorf("%w: extracting %s: %w", errLocalDisk, name, err)
		}
		if err != nil {
			return downloadError(ctx, fmt.Errorf("extracting %s: %w", name, err))
		}
		if closeErr != nil {
			return fmt.Errorf("%w: extracting %s: %w", errLocalDisk, name, closeErr)
		}
		found[name] = true
	}

	// Read what is left after the tar end, so size and digest cover the whole layer.
	if _, err = io.Copy(io.Discard, stream); err != nil {
		return downloadError(ctx, fmt.Errorf("reading DB layer: %w", err))
	}
	if counted.read != layer.Size {
		return fmt.Errorf("DB layer size is %d bytes, expected %d", counted.read, layer.Size)
	}
	if digest := fmt.Sprintf("sha256:%x", hasher.Sum(nil)); digest != layer.Digest {
		return fmt.Errorf("DB layer digest is %s, expected %s", digest, layer.Digest)
	}
	for _, name := range wantFiles {
		if !found[name] {
			return fmt.Errorf("DB layer has no %s", name)
		}
	}
	return nil
}

// extractedFile is what downloadDB writes an extracted file to.
type extractedFile interface {
	io.Writer
	Sync() error
	Close() error
}

// createFile creates a new file for extraction. Tests replace it to inject
// write errors such as a full disk.
var createFile = func(path string) (extractedFile, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// errLocalDisk marks download errors caused by our own disk (for example a full
// disk) rather than by the source. The update loop reports them as install_error.
var errLocalDisk = errors.New("local disk error")

// downloadError explains why the download context ended (stall or overall cap),
// because the read error alone only says "context canceled" or "deadline exceeded".
func downloadError(ctx context.Context, err error) error {
	cause := context.Cause(ctx)
	switch {
	case cause == nil:
		return err
	case errors.Is(cause, context.DeadlineExceeded):
		return fmt.Errorf("download exceeded the overall limit: %w", err)
	default:
		return fmt.Errorf("%v: %w", cause, err)
	}
}

// stallReader counts the bytes read and resets the stall timer whenever data arrives.
type stallReader struct {
	reader  io.Reader
	timer   *time.Timer
	timeout time.Duration
	read    int64
}

func (r *stallReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.read += int64(n)
		r.timer.Reset(r.timeout)
	}
	return n, err
}
