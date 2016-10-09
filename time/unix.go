package time

import (
	"strconv"
	"time"
)

func UnixTimeNowToString() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}
