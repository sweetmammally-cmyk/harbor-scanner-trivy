package store

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ReportInlineLimit is the largest report kept inside the scan document, in BSON
// bytes. Larger reports go to GridFS (DEMAND section 10). It is half of MongoDB's
// 16 MiB document limit, leaving room for the rest of the scan document.
const ReportInlineLimit = 8 << 20

// ReportBucket is the GridFS bucket of large reports (collections reports.files
// and reports.chunks).
const ReportBucket = "reports"

// ReportStore keeps a scan's report inline or in GridFS, depending on its size.
// Use SaveWithReport, which keeps the order: upload, save, clean up on failure.
type ReportStore interface {
	// Attach puts the report on the scan: in scan.Report when its BSON size is
	// within the limit, otherwise in a GridFS file (metadata scan_id and
	// uploaded_at) whose id goes to scan.ReportGridFSID. Earlier files of the
	// same scan_id (from a retry) are deleted first.
	Attach(ctx context.Context, scan *Scan, report bson.M) error
	// Discard deletes the scan's GridFS file, if it has one.
	Discard(ctx context.Context, scan Scan) error
	// Load returns the report of a scan from the document or from GridFS; nil
	// when the scan has no report.
	Load(ctx context.Context, scan Scan) (bson.M, error)
}

// SaveWithReport attaches the report to the scan, then saves the scan document
// with save. When the save fails, the GridFS file uploaded for it is deleted at
// once (best effort), so no file is left without its scan.
func SaveWithReport(ctx context.Context, reports ReportStore, scan Scan, report bson.M,
	save func(ctx context.Context, scan Scan) error) error {
	if err := reports.Attach(ctx, &scan, report); err != nil {
		return err
	}
	if err := save(ctx, scan); err != nil {
		if discardErr := reports.Discard(ctx, scan); discardErr != nil {
			slog.Warn("could not delete the GridFS report of a scan that was not saved",
				slog.String("scan_id", scan.ID), slog.String("error", discardErr.Error()))
		}
		return err
	}
	return nil
}

// MongoReports is the MongoDB ReportStore.
type MongoReports struct {
	client *Client
	bucket *mongo.GridFSBucket
	limit  int
}

// NewMongoReports returns a ReportStore that keeps reports up to limit BSON bytes
// inline (ReportInlineLimit in production).
func NewMongoReports(client *Client, limit int) *MongoReports {
	bucket := client.Database().GridFSBucket(options.GridFSBucket().SetName(ReportBucket))
	return &MongoReports{client: client, bucket: bucket, limit: limit}
}

func (r *MongoReports) Attach(ctx context.Context, scan *Scan, report bson.M) error {
	data, err := bson.Marshal(report)
	if err != nil {
		return fmt.Errorf("encoding report of scan %s: %w", scan.ID, err)
	}
	if len(data) <= r.limit {
		scan.Report = report
		scan.ReportGridFSID = nil
		return nil
	}

	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()

	// A retry of the same scan: delete the files of the earlier attempt first.
	cursor, err := r.bucket.Find(ctx, bson.D{{Key: "metadata.scan_id", Value: scan.ID}})
	if err != nil {
		return fmt.Errorf("finding earlier reports of scan %s: %w", scan.ID, err)
	}
	var earlier []struct {
		ID bson.ObjectID `bson:"_id"`
	}
	if err = cursor.All(ctx, &earlier); err != nil {
		return fmt.Errorf("finding earlier reports of scan %s: %w", scan.ID, err)
	}
	for _, file := range earlier {
		if err = r.bucket.Delete(ctx, file.ID); err != nil {
			return fmt.Errorf("deleting earlier report of scan %s: %w", scan.ID, err)
		}
	}

	metadata := bson.D{{Key: "scan_id", Value: scan.ID}, {Key: "uploaded_at", Value: time.Now()}}
	id, err := r.bucket.UploadFromStream(ctx, scan.ID, bytes.NewReader(data),
		options.GridFSUpload().SetMetadata(metadata))
	if err != nil {
		return fmt.Errorf("storing report of scan %s in GridFS: %w", scan.ID, err)
	}
	scan.Report = nil
	scan.ReportGridFSID = &id
	return nil
}

func (r *MongoReports) Discard(ctx context.Context, scan Scan) error {
	if scan.ReportGridFSID == nil {
		return nil
	}
	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	if err := r.bucket.Delete(ctx, *scan.ReportGridFSID); err != nil {
		return fmt.Errorf("deleting report of scan %s: %w", scan.ID, err)
	}
	return nil
}

func (r *MongoReports) Load(ctx context.Context, scan Scan) (bson.M, error) {
	if scan.ReportGridFSID == nil {
		return scan.Report, nil
	}

	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	var data bytes.Buffer
	if _, err := r.bucket.DownloadToStream(ctx, *scan.ReportGridFSID, &data); err != nil {
		return nil, fmt.Errorf("reading report of scan %s from GridFS: %w", scan.ID, err)
	}
	var report bson.M
	if err := bson.Unmarshal(data.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("decoding report of scan %s: %w", scan.ID, err)
	}
	return report, nil
}

// MemoryReports is an in-memory ReportStore for unit tests.
type MemoryReports struct {
	limit int

	mu    sync.Mutex
	files map[bson.ObjectID]memoryFile
}

type memoryFile struct {
	scanID string
	data   []byte
}

func NewMemoryReports(limit int) *MemoryReports {
	return &MemoryReports{limit: limit, files: map[bson.ObjectID]memoryFile{}}
}

func (m *MemoryReports) Attach(_ context.Context, scan *Scan, report bson.M) error {
	data, err := bson.Marshal(report)
	if err != nil {
		return fmt.Errorf("encoding report of scan %s: %w", scan.ID, err)
	}
	if len(data) <= m.limit {
		scan.Report = report
		scan.ReportGridFSID = nil
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, file := range m.files {
		if file.scanID == scan.ID {
			delete(m.files, id)
		}
	}
	id := bson.NewObjectID()
	m.files[id] = memoryFile{scanID: scan.ID, data: data}
	scan.Report = nil
	scan.ReportGridFSID = &id
	return nil
}

func (m *MemoryReports) Discard(_ context.Context, scan Scan) error {
	if scan.ReportGridFSID == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, *scan.ReportGridFSID)
	return nil
}

func (m *MemoryReports) Load(_ context.Context, scan Scan) (bson.M, error) {
	if scan.ReportGridFSID == nil {
		return scan.Report, nil
	}
	m.mu.Lock()
	file, found := m.files[*scan.ReportGridFSID]
	m.mu.Unlock()
	if !found {
		return nil, fmt.Errorf("reading report of scan %s: %w", scan.ID, ErrNotFound)
	}
	var report bson.M
	if err := bson.Unmarshal(file.data, &report); err != nil {
		return nil, fmt.Errorf("decoding report of scan %s: %w", scan.ID, err)
	}
	return report, nil
}

var (
	_ ReportStore = (*MongoReports)(nil)
	_ ReportStore = (*MemoryReports)(nil)
)
