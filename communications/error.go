package communications

import "fmt"

type ErrorMessage struct {
	ErrorType  string `json:"errortype"`
	StatusCode int32  `json:"status"`
	Message    string `json:"message"`
}

func (em *ErrorMessage) String() string {
	return fmt.Sprintf("(%s) %s", em.ErrorType, em.Message)
}
