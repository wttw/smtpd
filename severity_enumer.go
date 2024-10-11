// Code generated by "enumer -json -trimprefix Severity -type Severity"; DO NOT EDIT.

package smtpd

import (
	"encoding/json"
	"fmt"
)

const _SeverityName = "DebugInfoWarnErrorFatalConnectCloseReadWrite"

var _SeverityIndex = [...]uint8{0, 5, 9, 13, 18, 23, 30, 35, 39, 44}

func (i Severity) String() string {
	if i < 0 || i >= Severity(len(_SeverityIndex)-1) {
		return fmt.Sprintf("Severity(%d)", i)
	}
	return _SeverityName[_SeverityIndex[i]:_SeverityIndex[i+1]]
}

var _SeverityValues = []Severity{0, 1, 2, 3, 4, 5, 6, 7, 8}

var _SeverityNameToValueMap = map[string]Severity{
	_SeverityName[0:5]:   0,
	_SeverityName[5:9]:   1,
	_SeverityName[9:13]:  2,
	_SeverityName[13:18]: 3,
	_SeverityName[18:23]: 4,
	_SeverityName[23:30]: 5,
	_SeverityName[30:35]: 6,
	_SeverityName[35:39]: 7,
	_SeverityName[39:44]: 8,
}

// SeverityString retrieves an enum value from the enum constants string name.
// Throws an error if the param is not part of the enum.
func SeverityString(s string) (Severity, error) {
	if val, ok := _SeverityNameToValueMap[s]; ok {
		return val, nil
	}
	return 0, fmt.Errorf("%s does not belong to Severity values", s)
}

// SeverityValues returns all values of the enum
func SeverityValues() []Severity {
	return _SeverityValues
}

// IsASeverity returns "true" if the value is listed in the enum definition. "false" otherwise
func (i Severity) IsASeverity() bool {
	for _, v := range _SeverityValues {
		if i == v {
			return true
		}
	}
	return false
}

// MarshalJSON implements the json.Marshaler interface for Severity
func (i Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface for Severity
func (i *Severity) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("Severity should be a string, got %s", data)
	}

	var err error
	*i, err = SeverityString(s)
	return err
}
