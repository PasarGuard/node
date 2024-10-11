package tools

import (
	"encoding/json"
	"net/http"
	"time"
)

func UtcTime() (*time.Time, error) {
	url := "https://worldtimeapi.org/api/timezone/utc"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body response
	if err = json.NewDecoder(resp.Body).Decode(&resp); err != nil {
		return nil, err
	}

	return body.UtcDatetime, nil
}

type response struct {
	Abbreviation string      `json:"abbreviation"`
	ClientIp     string      `json:"client_ip"`
	Datetime     time.Time   `json:"datetime"`
	DayOfWeek    int         `json:"day_of_week"`
	DayOfYear    int         `json:"day_of_year"`
	Dst          bool        `json:"dst"`
	DstFrom      interface{} `json:"dst_from"`
	DstOffset    int         `json:"dst_offset"`
	DstUntil     interface{} `json:"dst_until"`
	RawOffset    int         `json:"raw_offset"`
	Timezone     string      `json:"timezone"`
	UnixTime     int         `json:"unixtime"`
	UtcDatetime  *time.Time  `json:"utc_datetime"`
	UtcOffset    string      `json:"utc_offset"`
	WeekNumber   int         `json:"week_number"`
}
