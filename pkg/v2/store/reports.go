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

// ReportStore keeps a scan result's report inline or in GridFS, depending on
// its size. Use SaveWithReport, which keeps the order: upload, save, clean up.
type ReportStore interface {
	// Attach puts the report on scan.Result (which must be set): in
	// Result.Report when its BSON size is within the limit, otherwise in a new
	// GridFS file (metadata scan_id and uploaded_at) whose id goes to
	// Result.ReportGridFSID. Files of the previous result are left alone.
	Attach(ctx context.Context, scan *Scan, report bson.M) error
	// Discard deletes the GridFS file of the scan's result, if it has one.
	Discard(ctx context.Context, scan Scan) error
	// DiscardOthers deletes every GridFS file of the scan's _id except the one of
	// its result: the previous result's file, and files of attempts that failed.
	DiscardOthers(ctx context.Context, scan Scan) error
	// Load returns the report of a scan's result from the document or from
	// GridFS; nil when there is no report.
	Load(ctx context.Context, scan Scan) (bson.M, error)
}

// SaveWithReport attaches the report to the scan's result, then saves the scan
// document with save. When the save fails, the GridFS file uploaded for it is
// deleted at once and the previous result keeps its file. When the save
// succeeds, the previous result's file is deleted. Both deletes are best effort.
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
	if err := reports.DiscardOthers(ctx, scan); err != nil {
		slog.Warn("could not delete the GridFS report of the previous result",
			slog.String("scan_id", scan.ID), slog.String("error", err.Error()))
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
	// A copy, so the caller's result is not changed through the pointer.
	result := *scan.Result
	scan.Result = &result
	data, err := bson.Marshal(report)
	if err != nil {
		return fmt.Errorf("encoding report of scan %s: %w", scan.ID, err)
	}
	if len(data) <= r.limit {
		scan.Result.Report = report
		scan.Result.ReportGridFSID = nil
		return nil
	}

	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	metadata := bson.D{{Key: "scan_id", Value: scan.ID}, {Key: "uploaded_at", Value: time.Now()}}
	id, err := r.bucket.UploadFromStream(ctx, scan.ID, bytes.NewReader(data),
		options.GridFSUpload().SetMetadata(metadata))
	if err != nil {
		return fmt.Errorf("storing report of scan %s in GridFS: %w", scan.ID, err)
	}
	scan.Result.Report = nil
	scan.Result.ReportGridFSID = &id
	return nil
}

func (r *MongoReports) Discard(ctx context.Context, scan Scan) error {
	if scan.Result == nil || scan.Result.ReportGridFSID == nil {
		return nil
	}
	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	if err := r.bucket.Delete(ctx, *scan.Result.ReportGridFSID); err != nil {
		return fmt.Errorf("deleting report of scan %s: %w", scan.ID, err)
	}
	return nil
}

func (r *MongoReports) DiscardOthers(ctx context.Context, scan Scan) error {
	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	filter := bson.D{{Key: "metadata.scan_id", Value: scan.ID}}
	if scan.Result != nil && scan.Result.ReportGridFSID != nil {
		filter = append(filter, bson.E{Key: "_id", Value: bson.D{{Key: "$ne", Value: *scan.Result.ReportGridFSID}}})
	}
	cursor, err := r.bucket.Find(ctx, filter)
	if err != nil {
		return fmt.Errorf("finding old reports of scan %s: %w", scan.ID, err)
	}
	var files []struct {
		ID bson.ObjectID `bson:"_id"`
	}
	if err = cursor.All(ctx, &files); err != nil {
		return fmt.Errorf("finding old reports of scan %s: %w", scan.ID, err)
	}
	for _, file := range files {
		if err = r.bucket.Delete(ctx, file.ID); err != nil {
			return fmt.Errorf("deleting old report of scan %s: %w", scan.ID, err)
		}
	}
	return nil
}

func (r *MongoReports) Load(ctx context.Context, scan Scan) (bson.M, error) {
	if scan.Result == nil {
		return nil, nil
	}
	if scan.Result.ReportGridFSID == nil {
		return scan.Result.Report, nil
	}

	ctx, cancel := r.client.OperationContext(ctx)
	defer cancel()
	var data bytes.Buffer
	if _, err := r.bucket.DownloadToStream(ctx, *scan.Result.ReportGridFSID, &data); err != nil {
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
	// A copy, so the caller's result is not changed through the pointer.
	result := *scan.Result
	scan.Result = &result
	data, err := bson.Marshal(report)
	if err != nil {
		return fmt.Errorf("encoding report of scan %s: %w", scan.ID, err)
	}
	if len(data) <= m.limit {
		scan.Result.Report = report
		scan.Result.ReportGridFSID = nil
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := bson.NewObjectID()
	m.files[id] = memoryFile{scanID: scan.ID, data: data}
	scan.Result.Report = nil
	scan.Result.ReportGridFSID = &id
	return nil
}

func (m *MemoryReports) Discard(_ context.Context, scan Scan) error {
	if scan.Result == nil || scan.Result.ReportGridFSID == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, *scan.Result.ReportGridFSID)
	return nil
}

func (m *MemoryReports) DiscardOthers(_ context.Context, scan Scan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, file := range m.files {
		current := scan.Result != nil && scan.Result.ReportGridFSID != nil && *scan.Result.ReportGridFSID == id
		if file.scanID == scan.ID && !current {
			delete(m.files, id)
		}
	}
	return nil
}

func (m *MemoryReports) Load(_ context.Context, scan Scan) (bson.M, error) {
	if scan.Result == nil {
		return nil, nil
	}
	if scan.Result.ReportGridFSID == nil {
		return scan.Result.Report, nil
	}
	m.mu.Lock()
	file, found := m.files[*scan.Result.ReportGridFSID]
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
