package osin

import (
	"encoding/json"
	"net/http"
)

// Output the response in JSON
type ResponseOutputJSON struct {
}

func NewResponseOutputJSON() *ResponseOutputJSON {
	return &ResponseOutputJSON{}
}

func (o *ResponseOutputJSON) Output(rs *Response, w http.ResponseWriter, r *http.Request) error {
	// Add headers
	for i, k := range rs.Headers {
		for _, v := range k {
			w.Header().Add(i, v)
		}
	}

	if rs.Type == REDIRECT {
		// Output redirect with parameters
		u, err := rs.GetRedirectUrl()
		if err != nil {
			return err
		}
		w.Header().Add("Location", u)
		w.WriteHeader(302)
	} else {
		// Ouptut json
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(rs.StatusCode)
		data, err := json.Marshal(rs.Output)
		if err != nil {
			return err
		}
		w.Write(data)
	}
	return nil
}
