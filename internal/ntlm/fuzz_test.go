package ntlm

import "testing"

// The CHALLENGE_MESSAGE comes from the server before it is authenticated.
func FuzzClientAuthenticate(f *testing.F) {
	f.Add(challengeMessage(48))
	f.Add(challengeMessage(64))
	f.Add(challengeMessage(256))

	f.Fuzz(func(t *testing.T, cmsg []byte) {
		c := &Client{User: "user", Password: "password", TargetSPN: "cifs/server"}
		if _, err := c.Negotiate(); err != nil {
			t.Fatal(err)
		}
		_, _ = c.Authenticate(cmsg)
	})
}
