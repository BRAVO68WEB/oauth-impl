package passhash

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcryptAcceptsStdlibHash(t *testing.T) {
	h := Bcrypt(bcrypt.MinCost)
	sum, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if err := h.Verify(string(sum), "secret"); err != nil {
		t.Fatalf("Verify stdlib hash: %v", err)
	}
	if err := h.Verify(string(sum), "other"); err == nil {
		t.Fatal("wrong password verified")
	}

	encoded, err := h.Hash("secret")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte("secret")); err != nil {
		t.Fatalf("stdlib compare: %v", err)
	}
}

func TestBcryptNeedsRehashWhenCostDiffers(t *testing.T) {
	low := Bcrypt(bcrypt.MinCost)
	encoded, err := low.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	high := Bcrypt(bcrypt.MinCost + 1).(Rehasher)
	if !high.NeedsRehash(encoded) {
		t.Fatal("expected rehash when cost differs")
	}
	if low.(Rehasher).NeedsRehash(encoded) {
		t.Fatal("same cost should not rehash")
	}
}

func TestDefaultBcryptCostMatchesStdlib(t *testing.T) {
	if DefaultBcryptCost != bcrypt.DefaultCost {
		t.Fatalf("DefaultBcryptCost = %d, bcrypt.DefaultCost = %d", DefaultBcryptCost, bcrypt.DefaultCost)
	}
}

func smallArgon2() Hasher {
	return Argon2id(Argon2Params{
		Memory:      32,
		Iterations:  1,
		Parallelism: 1,
		SaltLen:     16,
		KeyLen:      16,
	})
}

func TestArgon2idRoundTrip(t *testing.T) {
	h := smallArgon2()
	encoded, err := h.Hash("secret")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$") {
		t.Fatalf("encoding %q", encoded)
	}
	if err := h.Verify(encoded, "secret"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := h.Verify(encoded, "other"); err == nil {
		t.Fatal("wrong password verified")
	}
	if h.(Rehasher).NeedsRehash(encoded) {
		t.Fatal("fresh hash should not need rehash")
	}
}

func TestArgon2idTamperedHashFails(t *testing.T) {
	h := smallArgon2()
	encoded, err := h.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	cut := strings.LastIndex(encoded, "$")
	if cut < 0 || cut+1 >= len(encoded) {
		t.Fatalf("encoding %q", encoded)
	}
	replacement := byte('A')
	if encoded[cut+1] == 'A' {
		replacement = 'B'
	}
	tampered := encoded[:cut+1] + string(replacement) + encoded[cut+2:]
	if err := h.Verify(tampered, "secret"); err == nil {
		t.Fatal("tampered hash verified")
	}
	if err := h.Verify("not-a-hash", "secret"); err == nil {
		t.Fatal("garbage hash verified")
	}
}

func TestArgon2idParamChangeNeedsRehash(t *testing.T) {
	first := smallArgon2()
	encoded, err := first.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	second := Argon2id(Argon2Params{
		Memory:      32,
		Iterations:  2,
		Parallelism: 1,
		SaltLen:     16,
		KeyLen:      16,
	}).(Rehasher)
	if !second.NeedsRehash(encoded) {
		t.Fatal("expected rehash when iterations differ")
	}
}

func TestFallbackVerifiesBcryptAndNeedsRehash(t *testing.T) {
	legacy := Bcrypt(bcrypt.MinCost)
	encoded, err := legacy.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}

	fb := Fallback(smallArgon2(), legacy)
	if fb.ID() != "argon2id" {
		t.Fatalf("ID = %s", fb.ID())
	}
	if err := fb.Verify(encoded, "secret"); err != nil {
		t.Fatalf("legacy verify: %v", err)
	}
	if err := fb.Verify(encoded, "other"); err == nil {
		t.Fatal("wrong legacy password verified")
	}
	if !fb.(Rehasher).NeedsRehash(encoded) {
		t.Fatal("bcrypt hash should need rehash under argon2id primary")
	}

	fresh, err := fb.Hash("secret")
	if err != nil {
		t.Fatal(err)
	}
	if fb.(Rehasher).NeedsRehash(fresh) {
		t.Fatal("fresh argon2id hash should not need rehash")
	}
	if err := fb.Verify(fresh, "secret"); err != nil {
		t.Fatalf("primary verify: %v", err)
	}
}

func TestDefaultArgon2Memory(t *testing.T) {
	if DefaultArgon2.Memory != 64*1024 || DefaultArgon2.Iterations != 3 || DefaultArgon2.Parallelism != 4 {
		t.Fatalf("DefaultArgon2 = %+v", DefaultArgon2)
	}
}
