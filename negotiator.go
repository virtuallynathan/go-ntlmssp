package ntlmssp

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"
)

//Negotiator is a http.Roundtripper decorator that automatically
//converts basic authentication to NTLM/Negotiate authentication when appropriate.
type Negotiator struct{ http.RoundTripper }

//RoundTrip sends the request to the server, handling any authentication
//re-sends as needed.
func (l Negotiator) RoundTrip(req *http.Request) (res *http.Response, err error) {
	body := bytes.Buffer{}

	if req.Body != nil {
		_, err = body.ReadFrom(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body.Close()
	}

	req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

	reqauth := authheader(req.Header.Get("Authorization"))
	if reqauth.IsBasic() {
		// first try anonymous, in case the server still finds us
		// authenticated from previous traffic
		req.Header.Del("Authorization")

		res, err = l.RoundTripper.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if res.StatusCode != 401 {
			return res, err
		}
	}

	resauth := authheader(res.Header.Get("Www-Authenticate"))
	if !resauth.IsNegotiate() {
		// Unauthorized, Negotiate not requested, let's try with basic auth
		res.Body.Close()
		req.Header.Set("Authorization", string(reqauth))
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

		res, err = l.RoundTripper.RoundTrip(req)
		if err != nil {
			return nil, err
		}
	}

	if res.StatusCode == 401 {
		resauth := authheader(res.Header.Get("Www-Authenticate"))
		if reqauth.IsBasic() && resauth.IsNegotiate() {
			// 401 with request:Basic and response:Negotiate
			res.Body.Close()

			// recycle credentials
			u, p, err := reqauth.GetBasicCreds()
			if err != nil {
				return nil, err
			}

			// send negotiate
			negotiateMessage := NewNegotiateMessage()

			// format for the Authorization request header is found here:
			// http://davenport.sourceforge.net/ntlm.html#ntlmHttpAuthentication
			// and https://msdn.microsoft.com/en-us/library/cc237505.aspx
			req.Header.Set("Authorization", "NTLM " + base64.StdEncoding.EncodeToString(negotiateMessage))
			req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

			res, err = l.RoundTripper.RoundTrip(req)
			if err != nil {
				return nil, err
			}

			// The body contents need to be read because the default Transport
			// does not attempt to reuse HTTP/1.0 or HTTP/1.1 TCP connections
			// ("keep-alive") unless the Body is read to completion and is closed.
			// Without this, the subsequent request will be treated as a brand new
			// tcp connection, which resets the NTLM handshake.
			// Reference: https://godoc.org/net/http#Response
			if res.Body != nil {
				_, err = body.ReadFrom(res.Body)
				if err != nil {
					return nil, err
				}
			}

			// receive challenge?
			resauth = authheader(res.Header.Get("Www-Authenticate"))
			challengeMessage, err := resauth.GetData()
			if err != nil {
				return nil, err
			}
			if !resauth.IsChallenge() || len(challengeMessage) == 0 {
				// Negotiation failed, let client deal with response
				return res, nil
			}
			res.Body.Close()

			// send authenticate
			authenticateMessage, err := ProcessChallenge(challengeMessage, u, p)
			if err != nil {
				return nil, err
			}

			// format for the Authorization request header is found here:
			// http://davenport.sourceforge.net/ntlm.html#ntlmHttpAuthentication
			// and https://msdn.microsoft.com/en-us/library/cc237505.aspx
			req.Header.Set("Authorization", "NTLM " + base64.StdEncoding.EncodeToString(authenticateMessage))
			req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

			res, err = l.RoundTripper.RoundTrip(req)
		}
	}

	return res, err
}
