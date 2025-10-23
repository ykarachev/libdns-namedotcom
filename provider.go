// namedotcom implements the libdns interfaces to manage name.com dns records

package namedotcom

import (
	"context"
	"fmt"

	"github.com/libdns/libdns"
)

// Provider implements the libdns interface for namedotcom
type Provider struct {
	nameClient
	Token  string `json:"api_token,omitempty"`
	User   string `json:"user,omitempty"`
	Server string `json:"server,omitempty"` // e.g. https://api.name.com or https://api.dev.name.com

}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	records, err := p.listAllRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	var result []libdns.Record

	for _, record := range records {
		rec, err := record.toLibDNSRecord(zone)
		if err != nil {
			return []libdns.Record{}, fmt.Errorf("could not decode name.com's response:  %w", err)
		}
		result = append(result, rec)
	}

	return result, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var appendedRecords []libdns.Record

	for _, record := range records {
		newRecord, err := p.upsertRecord(ctx, zone, record)
		if err != nil {
			return nil, err
		}
		appendedRecords = append(appendedRecords, newRecord)
	}

	return appendedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var setRecords []libdns.Record

	for _, record := range records {
		setRecord, err := p.upsertRecord(ctx, zone, record)
		if err != nil {
			return setRecords, err
		}
		setRecords = append(setRecords, setRecord)
	}

	return setRecords, nil
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	var deletedRecords []libdns.Record

	for _, record := range records {
		deletedRecord, err := p.deleteRecord(ctx, zone, record)
		if err != nil {
			return nil, err
		}
		deletedRecords = append(deletedRecords, deletedRecord)
	}

	return deletedRecords, nil
}

func (p *Provider) ListZones(ctx context.Context) ([]libdns.Zone, error) {
	zones, err := p.listZones(ctx)
	if err != nil {
		return nil, err
	}

	return zones, nil

}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
	_ libdns.ZoneLister     = (*Provider)(nil)
)
