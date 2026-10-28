package validation

import (
	"testing"
	"time"
)

var now = time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)

func validInput() OrderInput {
	return OrderInput{
		ParcelNumber: "R-12345.001", PropertyAddress: "100 Main St, Bentonville", State: "AR",
		County: "Benton", Jurisdiction: "Benton County Collector", TaxYear: 2025, OwnerName: "Jane Q. Public",
	}
}

func fields(errs Errors) map[string]string {
	m := map[string]string{}
	for _, e := range errs {
		m[e.Field] = e.Code
	}
	return m
}

func TestNormalize(t *testing.T) {
	in := Normalize(OrderInput{ParcelNumber: "  r-12  345 ", State: " ar ", County: " Benton   County ", PropertyAddress: "  1   Main  St "})
	if in.ParcelNumber != "R-12 345" || in.State != "AR" || in.County != "Benton County" || in.PropertyAddress != "1 Main St" {
		t.Fatalf("unexpected normalisation: %+v", in)
	}
}

func TestValidateOrderInput_Valid(t *testing.T) {
	if errs := ValidateOrderInput(Normalize(validInput()), now); len(errs) != 0 {
		t.Fatalf("expected valid, got %v", errs)
	}
}

func TestValidateOrderInput_Table(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*OrderInput)
		wantField string
		wantCode  string
	}{
		{"missing parcel", func(i *OrderInput) { i.ParcelNumber = "" }, "parcel_number", "required"},
		{"bad parcel chars", func(i *OrderInput) { i.ParcelNumber = "AB;DROP" }, "parcel_number", "invalid_format"},
		{"parcel too short", func(i *OrderInput) { i.ParcelNumber = "A1" }, "parcel_number", "invalid_format"},
		{"parcel all zeros", func(i *OrderInput) { i.ParcelNumber = "000-000" }, "parcel_number", "invalid_value"},
		{"missing address", func(i *OrderInput) { i.PropertyAddress = "" }, "property_address", "required"},
		{"short address", func(i *OrderInput) { i.PropertyAddress = "1 A" }, "property_address", "invalid_length"},
		{"bad state", func(i *OrderInput) { i.State = "ZZ" }, "state", "invalid_value"},
		{"missing state", func(i *OrderInput) { i.State = "" }, "state", "required"},
		{"missing county", func(i *OrderInput) { i.County = "" }, "county", "required"},
		{"county digits", func(i *OrderInput) { i.County = "B3nton" }, "county", "invalid_format"},
		{"missing jurisdiction", func(i *OrderInput) { i.Jurisdiction = "" }, "jurisdiction", "required"},
		{"jurisdiction injection", func(i *OrderInput) { i.Jurisdiction = "<script>" }, "jurisdiction", "invalid_format"},
		{"missing tax year", func(i *OrderInput) { i.TaxYear = 0 }, "tax_year", "required"},
		{"tax year too old", func(i *OrderInput) { i.TaxYear = 1980 }, "tax_year", "out_of_range"},
		{"tax year too far ahead", func(i *OrderInput) { i.TaxYear = 2030 }, "tax_year", "out_of_range"},
		{"bad owner", func(i *OrderInput) { i.OwnerName = "1234" }, "owner_name", "invalid_format"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			tc.mutate(&in)
			got := fields(ValidateOrderInput(Normalize(in), now))
			if got[tc.wantField] != tc.wantCode {
				t.Fatalf("want %s=%s, got %v", tc.wantField, tc.wantCode, got)
			}
		})
	}
}

func TestValidateOrderInput_AllowsNextTaxYearButNotProcessing(t *testing.T) {
	in := validInput()
	in.TaxYear = now.Year() + 1
	if errs := ValidateOrderInput(Normalize(in), now); len(errs) != 0 {
		t.Fatalf("next tax year should pass structural validation: %v", errs)
	}
	if got := fields(ValidateForProcessing(Normalize(in), now)); got["tax_year"] != "future_year" {
		t.Fatalf("expected future_year, got %v", got)
	}
}

func TestValidateForProcessing_RequiresOwner(t *testing.T) {
	in := validInput()
	in.OwnerName = ""
	if got := fields(ValidateForProcessing(Normalize(in), now)); got["owner_name"] != "required" {
		t.Fatalf("expected owner_name required, got %v", got)
	}
}

func TestValidateCertificateType(t *testing.T) {
	if errs := ValidateCertificateType("CURRENT_TAX"); len(errs) != 0 {
		t.Fatal("CURRENT_TAX should be valid")
	}
	if errs := ValidateCertificateType("NOPE"); len(errs) != 1 {
		t.Fatal("NOPE should be rejected")
	}
}
