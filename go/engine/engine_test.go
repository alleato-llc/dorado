package engine

import (
	"bytes"
	"testing"
)

// PBKDF2 with a low round count keeps the tests fast.
func fastOpts() PasswordOptions {
	o := DefaultOptions()
	o.KDF = KDFParams{Kind: Pbkdf2, Rounds: 1000, Prf: PrfHMACSHA256}
	return o
}

func TestPasswordRoundTripAndTampering(t *testing.T) {
	pw := []byte("hunter2")
	pt := []byte("a message that spans more than nothing")
	ct, err := EncryptPasswordBytes(pw, fastOpts(), pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct, pt) {
		t.Fatal("ciphertext equals plaintext")
	}
	back, err := DecryptPasswordBytes(pw, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, pt) {
		t.Fatal("round-trip mismatch")
	}
	if _, err := DecryptPasswordBytes([]byte("wrong"), ct); err == nil {
		t.Fatal("wrong password accepted")
	}
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 1
	if _, err := DecryptPasswordBytes(pw, bad); err == nil {
		t.Fatal("tampering accepted")
	}
}

func TestEveryMAC(t *testing.T) {
	for _, mac := range []MacID{MacSkein, MacHMAC, MacBLAKE3} {
		opts := fastOpts()
		opts.Mac = mac
		pt := []byte("authenticated by each MAC in turn")
		ct, err := EncryptPasswordBytes([]byte("pw"), opts, pt)
		if err != nil {
			t.Fatalf("mac %d: %v", mac, err)
		}
		back, err := DecryptPasswordBytes([]byte("pw"), ct)
		if err != nil || !bytes.Equal(back, pt) {
			t.Fatalf("mac %d round-trip", mac)
		}
		if _, err := DecryptPasswordBytes([]byte("nope"), ct); err == nil {
			t.Fatalf("mac %d wrong password accepted", mac)
		}
	}
}

func TestMultiChunkAcrossVariants(t *testing.T) {
	for _, v := range []Variant{T256, T512, T1024} {
		opts := fastOpts()
		opts.Variant = v
		opts.ChunkSize = uint32(v.BlockLen()) * 2 // small, forces several chunks
		pt := make([]byte, 1000)
		for i := range pt {
			pt[i] = byte(i)
		}
		ct, err := EncryptPasswordBytes([]byte("pw"), opts, pt)
		if err != nil {
			t.Fatalf("variant %d: %v", v, err)
		}
		back, err := DecryptPasswordBytes([]byte("pw"), ct)
		if err != nil || !bytes.Equal(back, pt) {
			t.Fatalf("variant %d multi-chunk round-trip", v)
		}
	}
}

func TestLabelBinding(t *testing.T) {
	opts := fastOpts()
	opts.Label = []byte("backup-2026")
	ct, err := EncryptPasswordBytes([]byte("pw"), opts, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(bytes.NewReader(ct))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(info.Label, []byte("backup-2026")) {
		t.Fatal("label not stored")
	}
	if info.Version != 4 {
		t.Fatalf("version %d, want 4", info.Version)
	}
	if _, err := DecryptPasswordBytesExpecting([]byte("pw"), []byte("backup-2026"), ct); err != nil {
		t.Fatalf("matching label failed: %v", err)
	}
	if _, err := DecryptPasswordBytesExpecting([]byte("pw"), []byte("other"), ct); err == nil {
		t.Fatal("label mismatch accepted")
	}
}

func TestTruncationRejected(t *testing.T) {
	opts := fastOpts()
	opts.ChunkSize = 64
	pt := make([]byte, 200)
	for i := range pt {
		pt[i] = byte(i)
	}
	ct, err := EncryptPasswordBytes([]byte("pw"), opts, pt)
	if err != nil {
		t.Fatal(err)
	}
	for _, cut := range []int{1, 33, 80, 150} {
		if _, err := DecryptPasswordBytes([]byte("pw"), ct[:len(ct)-cut]); err == nil {
			t.Fatalf("truncation by %d accepted", cut)
		}
	}
}

func TestRawCTRRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 32)
	tweak := make([]byte, 16)
	pt := []byte("raw CTR ciphertext, any length, no authentication")

	var enc bytes.Buffer
	if err := RawCTRStream(T256, key, tweak, iv, bytes.NewReader(pt), &enc); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc.Bytes(), pt) {
		t.Fatal("raw CTR did not transform")
	}
	var dec bytes.Buffer
	if err := RawCTRStream(T256, key, tweak, iv, bytes.NewReader(enc.Bytes()), &dec); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Bytes(), pt) {
		t.Fatal("raw CTR round-trip mismatch")
	}
}
