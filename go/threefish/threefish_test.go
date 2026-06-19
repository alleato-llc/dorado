package threefish

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

const tweakHex = "000102030405060708090A0B0C0D0E0F"

// Official known-answer vectors (Crypto++ threefish.txt), one per block size.
func TestKnownAnswerVectors(t *testing.T) {
	cases := []struct {
		name           string
		newFn          func(key, tweak []byte) (cipher.Block, error)
		key, pt, ct    string
	}{
		{
			"256",
			New256,
			"101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F",
			"FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
			"E0D091FF0EEA8FDFC98192E62ED80AD59D865D08588DF476657056B5955E97DF",
		},
		{
			"512",
			New512,
			"101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F" +
				"303132333435363738393A3B3C3D3E3F4041424344454647 48494A4B4C4D4E4F",
			"FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
				"DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0",
			"E304439626D45A2CB401CAD8D636249A6338330EB06D45DD8B36B90E97254779" +
				"272A0A8D99463504784420EA18C9A725AF11DFFEA10162348927673D5C1CAF3D",
		},
		{
			"1024",
			New1024,
			"101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F" +
				"303132333435363738393A3B3C3D3E3F4041424344454647 48494A4B4C4D4E4F" +
				"505152535455565758595A5B5C5D5E5F6061626364656667 68696A6B6C6D6E6F" +
				"707172737475767778797A7B7C7D7E7F8081828384858687 88898A8B8C8D8E8F",
			"FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
				"DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0" +
				"BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A0" +
				"9F9E9D9C9B9A99989796959493929190 8F8E8D8C8B8A89888786858483828180",
			"A6654DDBD73CC3B05DD777105AA849BCE49372EAAFFC5568D254771BAB85531C" +
				"94F780E7FFAAE430D5D8AF8C70EEBBE1760F3B42B737A89CB363490D670314BD" +
				"8AA41EE63C2E1F45FBD477922F8360B388D6125EA6C7AF0AD7056D01796E90C8" +
				"3313F4150A5716B30ED5F569288AE974CE2B4347926FCE57DE44512177DD7CDE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := unhex(t, tc.key)
			tweak := unhex(t, tweakHex)
			pt := unhex(t, tc.pt)
			want := unhex(t, tc.ct)

			c, err := tc.newFn(key, tweak)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(pt))
			c.Encrypt(got, pt)
			if !bytes.Equal(got, want) {
				t.Fatalf("encrypt mismatch:\n got %x\nwant %x", got, want)
			}
			c.Decrypt(got, got)
			if !bytes.Equal(got, pt) {
				t.Fatalf("decrypt did not round-trip")
			}
		})
	}
}

func TestConstructorErrors(t *testing.T) {
	if _, err := New256(make([]byte, 16), make([]byte, 16)); err == nil {
		t.Fatal("expected error for short key")
	}
	if _, err := New256(make([]byte, 32), make([]byte, 8)); err == nil {
		t.Fatal("expected error for short tweak")
	}
}

// Threefish plugs into the standard library's CTR mode via cipher.Block, and the
// same stream decrypts. This is the Go equivalent of dorado's ctr_apply, for
// free from the stdlib.
func TestStdlibCTRRoundTrips(t *testing.T) {
	key := make([]byte, 32)
	tweak := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := New256(key, tweak)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, block.BlockSize())

	plain := []byte("any length, not just one block -- CTR handles it")
	ct := make([]byte, len(plain))
	cipher.NewCTR(block, iv).XORKeyStream(ct, plain)
	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext equals plaintext")
	}

	out := make([]byte, len(ct))
	cipher.NewCTR(block, iv).XORKeyStream(out, ct)
	if !bytes.Equal(out, plain) {
		t.Fatal("CTR did not round-trip")
	}
}
