// Package validation implements UTS-GO-104: backend validation for parcel, property,
// tax year, jurisdiction and order information.
package validation

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	MinTaxYear = 1990
)

var (
	parcelRe       = regexp.MustCompile(`^[A-Z0-9][A-Z0-9\-\. /]{2,31}$`)
	jurisdictionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 .,'&\-/]{1,119}$`)
	countyRe       = regexp.MustCompile(`^[A-Za-z][A-Za-z .'\-]{1,59}$`)
	personRe       = regexp.MustCompile(`^[\p{L}][\p{L} .,'&\-]{1,119}$`)
	spaceRe        = regexp.MustCompile(`\s+`)
)

var usStates = map[string]struct{}{}

func init() {
	for _, s := range strings.Fields(`AL AK AZ AR CA CO CT DE DC FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO
		MT NE NV NH NJ NM NY NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY`) {
		usStates[s] = struct{}{}
	}
}

// CertificateTypes lists the certificate products a tax order may request.
var CertificateTypes = map[string]struct{}{
	"CURRENT_TAX":    {},
	"DELINQUENT_TAX": {},
	"TAX_HISTORY":    {},
	"PAID_RECEIPT":   {},
}

// OrderInput is the client-supplied portion of a property-tax order.
type OrderInput struct {
	ParcelNumber    string `json:"parcel_number"`
	PropertyAddress string `json:"property_address"`
	State           string `json:"state"`
	County          string `json:"county"`
	Jurisdiction    string `json:"jurisdiction"`
	TaxYear         int    `json:"tax_year"`
	OwnerName       string `json:"owner_name"`
}

type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Errors []FieldError

func (e Errors) Error() string {
	parts := make([]string, len(e))
	for i, fe := range e {
		parts[i] = fe.Field + ": " + fe.Message
	}
	return strings.Join(parts, "; ")
}

func (e *Errors) add(field, code, msg string) { *e = append(*e, FieldError{field, code, msg}) }

func clean(s string) string { return spaceRe.ReplaceAllString(strings.TrimSpace(s), " ") }

// Normalize trims, collapses whitespace and canonicalises case. Always call it before validating
// or persisting so equivalent inputs ("tx" vs " TX ") compare equal.
func Normalize(in OrderInput) OrderInput {
	in.ParcelNumber = strings.ToUpper(clean(in.ParcelNumber))
	in.PropertyAddress = clean(in.PropertyAddress)
	in.State = strings.ToUpper(clean(in.State))
	in.County = clean(in.County)
	in.Jurisdiction = clean(in.Jurisdiction)
	in.OwnerName = clean(in.OwnerName)
	return in
}

// ValidateOrderInput checks structural correctness; it is what create and update enforce.
func ValidateOrderInput(in OrderInput, now time.Time) Errors {
	var errs Errors

	// Parcel
	switch {
	case in.ParcelNumber == "":
		errs.add("parcel_number", "required", "parcel number is required")
	case !parcelRe.MatchString(in.ParcelNumber):
		errs.add("parcel_number", "invalid_format", "parcel number must be 3-32 characters: letters, digits, '-', '.', '/' or spaces")
	case strings.Trim(in.ParcelNumber, "-. /0") == "":
		errs.add("parcel_number", "invalid_value", "parcel number cannot consist only of zeros or separators")
	}

	// Property
	switch {
	case in.PropertyAddress == "":
		errs.add("property_address", "required", "property address is required")
	case len(in.PropertyAddress) < 5 || len(in.PropertyAddress) > 200:
		errs.add("property_address", "invalid_length", "property address must be between 5 and 200 characters")
	}
	if in.OwnerName != "" && !personRe.MatchString(in.OwnerName) {
		errs.add("owner_name", "invalid_format", "owner name contains unsupported characters or is too short/long")
	}

	// Jurisdiction
	if in.State == "" {
		errs.add("state", "required", "state is required")
	} else if _, ok := usStates[in.State]; !ok {
		errs.add("state", "invalid_value", fmt.Sprintf("%q is not a valid two-letter US state code", in.State))
	}
	if in.County == "" {
		errs.add("county", "required", "county is required")
	} else if !countyRe.MatchString(in.County) {
		errs.add("county", "invalid_format", "county name contains unsupported characters")
	}
	if in.Jurisdiction == "" {
		errs.add("jurisdiction", "required", "taxing jurisdiction is required")
	} else if !jurisdictionRe.MatchString(in.Jurisdiction) {
		errs.add("jurisdiction", "invalid_format", "jurisdiction contains unsupported characters")
	}

	// Tax year
	maxYear := now.Year() + 1
	switch {
	case in.TaxYear == 0:
		errs.add("tax_year", "required", "tax year is required")
	case in.TaxYear < MinTaxYear || in.TaxYear > maxYear:
		errs.add("tax_year", "out_of_range", fmt.Sprintf("tax year must be between %d and %d", MinTaxYear, maxYear))
	}
	return errs
}

// ValidateForProcessing applies the stricter business rules that must hold before an order
// may leave CREATED and be worked: owner of record present and tax year not in the future.
func ValidateForProcessing(in OrderInput, now time.Time) Errors {
	errs := ValidateOrderInput(in, now)
	if in.OwnerName == "" {
		errs.add("owner_name", "required", "owner of record is required before processing")
	}
	if in.TaxYear > now.Year() {
		errs.add("tax_year", "future_year", "tax year cannot be in the future when processing an order")
	}
	return errs
}

func ValidateCertificateType(t string) Errors {
	var errs Errors
	if _, ok := CertificateTypes[t]; !ok {
		errs.add("type", "invalid_value", "type must be one of CURRENT_TAX, DELINQUENT_TAX, TAX_HISTORY, PAID_RECEIPT")
	}
	return errs
}
