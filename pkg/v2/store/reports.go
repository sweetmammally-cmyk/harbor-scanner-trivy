package store

import (
	"bytes"
	"context"
	"fmt"
	"sync"

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
type ReportStore interface {
	// Attach puts the report on the scan: in scan.Report when it is small enough,
	// otherwise in GridFS, with its id in scan.ReportGridFSID. The caller then
	// saves the scan document.
	Attach(ctx context.Context, scan *Scan, report bson.M) error
	// Load returns the report of a scan from the document or from GridFS; nil
	// when the scan has no report.
	Load(ctx context.Context, scan Scan) (bson.M, error)
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
	id, err := r.bucket.UploadFromStream(ctx, scan.ID, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("storing report of scan %s in GridFS: %w", scan.ID, err)
	}
	scan.Report = nil
	scan.ReportGridFSID = &id
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
	files map[bson.ObjectID][]byte
}

func NewMemoryReports(limit int) *MemoryReports {
	return &MemoryReports{limit: limit, files: map[bson.ObjectID][]byte{}}
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
	id := bson.NewObjectID()
	m.files[id] = data
	scan.Report = nil
	scan.ReportGridFSID = &id
	return nil
}

func (m *MemoryReports) Load(_ context.Context, scan Scan) (bson.M, error) {
	if scan.ReportGridFSID == nil {
		return scan.Report, nil
	}
	m.mu.Lock()
	data, found := m.files[*scan.ReportGridFSID]
	m.mu.Unlock()
	if !found {
		return nil, fmt.Errorf("reading report of scan %s: %w", scan.ID, ErrNotFound)
	}
	var report bson.M
	if err := bson.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decoding report of scan %s: %w", scan.ID, err)
	}
	return report, nil
}

var (
	_ ReportStore = (*MongoReports)(nil)
	_ ReportStore = (*MemoryReports)(nil)
)
