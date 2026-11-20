// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nkeys

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a controllable time source for deterministic rotation tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestRotationSet(t *testing.T, opts ...RotationOption) *RotationSet {
	t.Helper()
	clock := newFakeClock()
	all := append([]RotationOption{withClock(clock.now)}, opts...)
	rs, err := NewRotationSet(all...)
	if err != nil {
		t.Fatalf("NewRotationSet: %v", err)
	}
	return rs
}

func mustOperator(t *testing.T) KeyPair {
	t.Helper()
	kp, err := CreateOperator()
	if err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	return kp
}

func mustPublic(t *testing.T, kp KeyPair) string {
	t.Helper()
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	return pub
}

// TestRotationSetActivateAndSign covers requirement 1 and 2: one active
// signing key, signing always uses the active private key.
func TestRotationSetActivateAndSign(t *testing.T) {
	rs := newTestRotationSet(t)
	first := mustOperator(t)
	second := mustOperator(t)

	if _, err := rs.ActivePublicKey(); err != ErrRotationNoActive {
		t.Fatalf("expected ErrRotationNoActive, got %v", err)
	}
	if err := rs.ActivateGeneration(first, 1, time.Time{}); err != nil {
		t.Fatalf("ActivateGeneration first: %v", err)
	}
	activePub, err := rs.ActivePublicKey()
	if err != nil {
		t.Fatalf("ActivePublicKey: %v", err)
	}
	if activePub != mustPublic(t, first) {
		t.Fatalf("active public key mismatch")
	}
	gen, err := rs.ActiveGeneration()
	if err != nil || gen != 1 {
		t.Fatalf("ActiveGeneration = %d, %v; want 1", gen, err)
	}

	input := []byte("operator JWT")
	sig, err := rs.Sign(input)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// The signature must come from the active private key.
	if err := first.Verify(input, sig); err != nil {
		t.Fatalf("signature not produced by active key: %v", err)
	}
	if err := second.Verify(input, sig); err == nil {
		t.Fatalf("inactive key verified the active key's signature")
	}
	if err := rs.Verify(time.Now(), input, sig); err != nil {
		t.Fatalf("Verify with active member: %v", err)
	}

	// Rotate to the second generation; the first key remains as a verifier.
	if err := rs.ActivateGeneration(second, 2, time.Time{}); err != nil {
		t.Fatalf("ActivateGeneration second: %v", err)
	}
	activePub, _ = rs.ActivePublicKey()
	if activePub != mustPublic(t, second) {
		t.Fatalf("active key did not rotate")
	}
	sig2, err := rs.Sign(input)
	if err != nil {
		t.Fatalf("Sign after rotation: %v", err)
	}
	if err := second.Verify(input, sig2); err != nil {
		t.Fatalf("new signature not from the new active key: %v", err)
	}
	// Overlap window: the old credential still verifies.
	if err := rs.Verify(time.Now(), input, sig); err != nil {
		t.Fatalf("old credential rejected during overlap window: %v", err)
	}
	if err := rs.Verify(time.Now(), input, sig2); err != nil {
		t.Fatalf("new credential rejected: %v", err)
	}
}

// TestRotationSetMultipleVerificationKeys covers requirement 1: many
// verification-only members coexist with the single active signer.
func TestRotationSetMultipleVerificationKeys(t *testing.T) {
	rs := newTestRotationSet(t)
	signer := mustOperator(t)
	if err := rs.ActivateGeneration(signer, 1, time.Time{}); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{mustPublic(t, signer): true}
	for i := 0; i < 3; i++ {
		full, err := CreateOperator()
		if err != nil {
			t.Fatal(err)
		}
		pub := mustPublic(t, full)
		if err := rs.AddVerificationKey(pub, time.Time{}); err != nil {
			t.Fatalf("AddVerificationKey: %v", err)
		}
		seen[pub] = true
		// The set stores a public-key-only member: it cannot be used to sign.
		pubOnly, err := FromPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pubOnly.Sign([]byte("x")); err != ErrCannotSign {
			t.Fatalf("pub-only Sign: expected ErrCannotSign, got %v", err)
		}
	}

	snap := rs.Snapshot()
	if len(snap.Members) != 4 {
		t.Fatalf("expected 4 members, got %d", len(snap.Members))
	}
	for _, m := range snap.Members {
		if !seen[m.PublicKey] {
			t.Fatalf("unexpected member %q", m.PublicKey)
		}
	}

	// Adding the same key twice is rejected.
	if err := rs.AddVerificationKey(mustPublic(t, signer), time.Time{}); err != ErrRotationMemberExists {
		t.Fatalf("duplicate member: expected ErrRotationMemberExists, got %v", err)
	}
}

// TestRotationSetVerificationByMessageTime covers requirement 2: verification
// selects the member valid at the message time, not just the current list.
func TestRotationSetVerificationByMessageTime(t *testing.T) {
	clock := newFakeClock()
	rs, err := NewRotationSet(withClock(clock.now))
	if err != nil {
		t.Fatal(err)
	}
	old := mustOperator(t)
	new := mustOperator(t)

	t0 := clock.now()
	t1 := t0.Add(time.Hour)
	t2 := t1.Add(time.Hour)

	if err := rs.ActivateGeneration(old, 1, t0); err != nil {
		t.Fatal(err)
	}
	if err := rs.ActivateGeneration(new, 2, t1); err != nil {
		t.Fatal(err)
	}

	// A credential signed by the new key before it activated must not verify at
	// that earlier message time, even though the key is current later. No member
	// was valid then, so the signature cannot match any candidate.
	input := []byte("credential")
	sigNew, err := new.Sign(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Verify(t0.Add(time.Minute), input, sigNew); err == nil {
		t.Fatalf("future key verified before activation")
	}

	// An old-key credential verifies while the old key is still active.
	sigOld, err := old.Sign(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.Verify(t0.Add(30*time.Minute), input, sigOld); err != nil {
		t.Fatalf("old credential failed inside its validity window: %v", err)
	}

	// After the old key is revoked at t2, old-key credentials dated before t2
	// still verify under the default reject policy because the member was valid
	// at that message time.
	if err := rs.Revoke(mustPublic(t, old), t2); err != nil {
		t.Fatal(err)
	}
	if err := rs.Verify(t0.Add(30*time.Minute), input, sigOld); err != nil {
		t.Fatalf("pre-revocation credential rejected: %v", err)
	}
	// Before any key activated, there is no valid member.
	if err := rs.Verify(t0.Add(-time.Minute), input, sigOld); err != ErrRotationNoValidMember {
		t.Fatalf("expected ErrRotationNoValidMember before activation, got %v", err)
	}
	// An old-key credential dated after revocation cannot verify: the new key
	// is the valid member then and its signature check fails.
	if err := rs.Verify(t2.Add(time.Minute), input, sigOld); err == nil {
		t.Fatal("revoked-key credential verified after revocation")
	}
}

// TestRotationSetRevocationPolicies covers requirement 3: an explicit policy
// decides the fate of revoked-key credentials whose stamped time lies within
// the allowed clock skew after revocation.
func TestRotationSetRevocationPolicies(t *testing.T) {
	clock := newFakeClock()
	skew := 5 * time.Minute

	build := func(t *testing.T, policy RevocationPolicy) (*RotationSet, []byte, []byte, time.Time) {
		rs, err := NewRotationSet(withClock(clock.now), WithClockSkew(skew), WithRevocationPolicy(policy))
		if err != nil {
			t.Fatal(err)
		}
		old := mustOperator(t)
		t0 := clock.now()
		revokeAt := t0.Add(time.Hour)
		if err := rs.ActivateGeneration(old, 1, t0); err != nil {
			t.Fatal(err)
		}
		input := []byte("jwt")
		sig, err := old.Sign(input)
		if err != nil {
			t.Fatal(err)
		}
		if err := rs.Revoke(mustPublic(t, old), revokeAt); err != nil {
			t.Fatal(err)
		}
		return rs, input, sig, revokeAt
	}

	t.Run("reject policy", func(t *testing.T) {
		rs, input, sig, revokeAt := build(t, RejectRevoked)
		// A credential stamped after revocation, even within skew, is rejected.
		if err := rs.Verify(revokeAt.Add(time.Minute), input, sig); err != ErrRotationNoValidMember {
			t.Fatalf("reject policy accepted revoked credential: %v", err)
		}
		// A credential stamped before revocation verifies: the member was valid
		// at that message time.
		if err := rs.Verify(revokeAt.Add(-time.Minute), input, sig); err != nil {
			t.Fatalf("pre-revocation credential rejected: %v", err)
		}
	})

	t.Run("grace policy", func(t *testing.T) {
		rs, input, sig, revokeAt := build(t, GracePeriodRevoked)
		// Within the grace window after revocation: accepted.
		if err := rs.Verify(revokeAt.Add(time.Minute), input, sig); err != nil {
			t.Fatalf("grace policy rejected within skew: %v", err)
		}
		// Just inside the skew boundary: accepted.
		if err := rs.Verify(revokeAt.Add(skew-time.Second), input, sig); err != nil {
			t.Fatalf("grace policy rejected at boundary: %v", err)
		}
		// At or beyond the skew boundary: rejected.
		if err := rs.Verify(revokeAt.Add(skew), input, sig); err != ErrRotationNoValidMember {
			t.Fatalf("grace policy accepted at skew boundary: %v", err)
		}
		if err := rs.Verify(revokeAt.Add(skew+time.Second), input, sig); err != ErrRotationNoValidMember {
			t.Fatalf("grace policy accepted outside window: %v", err)
		}
		// Before revocation the member was valid, so it still verifies.
		if err := rs.Verify(revokeAt.Add(-time.Minute), input, sig); err != nil {
			t.Fatalf("pre-revocation credential rejected under grace policy: %v", err)
		}
	})

	t.Run("bad signature still fails in grace", func(t *testing.T) {
		rs, input, sig, revokeAt := build(t, GracePeriodRevoked)
		tampered := append([]byte{}, input...)
		tampered[0]++
		err := rs.Verify(revokeAt.Add(time.Minute), tampered, sig)
		if err == nil || err == ErrRotationNoValidMember {
			t.Fatalf("tampered input should fail signature check, got %v", err)
		}
	})
}

// TestRotationSetGenerationConflicts covers requirement 4: only one concurrent
// activation of a generation succeeds; rollback and zero are rejected.
func TestRotationSetGenerationConflicts(t *testing.T) {
	rs := newTestRotationSet(t)
	first := mustOperator(t)
	if err := rs.ActivateGeneration(first, 10, time.Time{}); err != nil {
		t.Fatal(err)
	}

	conflict := mustOperator(t)
	if err := rs.ActivateGeneration(conflict, 10, time.Time{}); err != ErrRotationGenerationConflict {
		t.Fatalf("same generation: expected ErrRotationGenerationConflict, got %v", err)
	}
	if err := rs.ActivateGeneration(conflict, 9, time.Time{}); err != ErrRotationGenerationRollback {
		t.Fatalf("rollback: expected ErrRotationGenerationRollback, got %v", err)
	}
	if err := rs.ActivateGeneration(conflict, 0, time.Time{}); err != ErrRotationInvalidGeneration {
		t.Fatalf("zero generation: expected ErrRotationInvalidGeneration, got %v", err)
	}

	// The failed activations must not have changed the active key.
	active, err := rs.ActivePublicKey()
	if err != nil || active != mustPublic(t, first) {
		t.Fatalf("active key changed after failed activation: %q, %v", active, err)
	}

	// The next generation succeeds.
	if err := rs.ActivateGeneration(conflict, 11, time.Time{}); err != nil {
		t.Fatalf("next generation failed: %v", err)
	}

	// Concurrent activations of the same generation: exactly one wins.
	const n = 32
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			kp := mustOperator(t)
			errs[i] = rs.ActivateGeneration(kp, 42, time.Time{})
		}(i)
	}
	wg.Wait()
	var ok, failed int
	for _, err := range errs {
		if err == nil {
			ok++
		} else if err != ErrRotationGenerationConflict {
			t.Fatalf("unexpected concurrent activation error: %v", err)
		} else {
			failed++
		}
	}
	if ok != 1 || failed != n-1 {
		t.Fatalf("expected 1 success and %d conflicts, got %d and %d", n-1, ok, failed)
	}
}

// TestRotationSetRejectsBadSeedsAndKeys covers requirement 4's inherited
// defenses: seed validation and small-order/identity public key rejection,
// plus the "nkeys:" error prefix.
func TestRotationSetRejectsBadSeedsAndKeys(t *testing.T) {
	rs := newTestRotationSet(t)

	// Bad seed: existing DecodeSeed rules apply and migration fails without
	// changing the set.
	badSeed := []byte("not-a-seed")
	if err := rs.ActivateSeedGeneration(badSeed, 1, time.Time{}); err == nil {
		t.Fatal("bad seed migration unexpectedly succeeded")
	}
	// A well-formed seed failing on a rotation rule still carries the nkeys
	// error prefix used by the package.
	validButConflicting := mustOperator(t)
	conflictingSeed, err := validButConflicting.Seed()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.ActivateSeedGeneration(conflictingSeed, 0, time.Time{}); err == nil ||
		!strings.HasPrefix(err.Error(), "nkeys:") {
		t.Fatalf("zero generation: expected an nkeys-prefixed error, got %v", err)
	}

	// Small-order/identity public keys are rejected via decodePublicKey.
	identity, err := Encode(PrefixByteOperator, make([]byte, ed25519.PublicKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.AddVerificationKey(string(identity), time.Time{}); err != ErrInvalidPublicKey {
		t.Fatalf("identity point: expected ErrInvalidPublicKey, got %v", err)
	}
	smallOrder, err := Encode(PrefixByteOperator, append([]byte{1}, make([]byte, 31)...))
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.AddVerificationKey(string(smallOrder), time.Time{}); err != ErrInvalidPublicKey {
		t.Fatalf("small-order key: expected ErrInvalidPublicKey, got %v", err)
	}

	// A public-key-only KeyPair cannot be activated as the signer.
	pubOnly, err := FromPublicKey(mustPublic(t, mustOperator(t)))
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.ActivateGeneration(pubOnly, 1, time.Time{}); err != ErrCannotSign {
		t.Fatalf("pub-only activation: expected ErrCannotSign, got %v", err)
	}

	// Curve keys are not allowed in a signing rotation set. A static encoded
	// curve public key is used so this check stays safe in FIPS-only mode, where
	// runtime X25519 operations panic.
	const curvePublic = "XCPJHDOMNODMVYPCUW5DEUHOKNPC6YZQ5AMFMH3OFZUJO35TEPWTCVG4"
	if err := rs.AddVerificationKey(curvePublic, time.Time{}); err != ErrInvalidCurveKeyOperation {
		t.Fatalf("curve member: expected ErrInvalidCurveKeyOperation, got %v", err)
	}

	// Mixed roles are rejected.
	operator := mustOperator(t)
	if err := rs.ActivateGeneration(operator, 1, time.Time{}); err != nil {
		t.Fatal(err)
	}
	account, err := CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.ActivateGeneration(account, 2, time.Time{}); err != ErrIncompatibleKey {
		t.Fatalf("mixed prefix: expected ErrIncompatibleKey, got %v", err)
	}
}

// TestRotationSetSeedWipeOnFailedMigration covers requirement 5: failed
// migration zeroes every handled seed, including the caller's buffer.
func TestRotationSetSeedWipeOnFailedMigration(t *testing.T) {
	rs := newTestRotationSet(t)
	first := mustOperator(t)
	firstSeed, err := first.Seed()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.ActivateSeedGeneration(append([]byte{}, firstSeed...), 1, time.Time{}); err != nil {
		t.Fatal(err)
	}

	// A conflicting generation must zero the caller's seed buffer on failure.
	second := mustOperator(t)
	secondSeed, err := second.Seed()
	if err != nil {
		t.Fatal(err)
	}
	buf := append([]byte{}, secondSeed...)
	err = rs.ActivateSeedGeneration(buf, 1, time.Time{})
	if err != ErrRotationGenerationConflict {
		t.Fatalf("expected conflict error, got %v", err)
	}
	if !bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatalf("caller seed buffer was not zeroized after failed migration")
	}
	if len(rs.Snapshot().Members) != 1 {
		t.Fatalf("failed migration mutated the set")
	}

	// A malformed seed is zeroized as well.
	malformed := []byte("SUTOTALLY-NOT-A-VALID-SEED")
	orig := append([]byte{}, malformed...)
	if err := rs.ActivateSeedGeneration(malformed, 2, time.Time{}); err == nil {
		t.Fatal("expected malformed seed migration to fail")
	}
	if bytes.Equal(malformed, orig) {
		t.Fatal("malformed seed buffer was not zeroized")
	}

	// A successful migration leaves the caller's buffer intact.
	okBuf := append([]byte{}, secondSeed...)
	if err := rs.ActivateSeedGeneration(okBuf, 2, time.Time{}); err != nil {
		t.Fatalf("successful migration: %v", err)
	}
	if !bytes.Equal(okBuf, secondSeed) {
		t.Fatal("successful migration must not modify the caller's buffer")
	}
}

// TestRotationSetWipe covers requirement 5: shutdown zeroes all held seeds and
// closes the set.
func TestRotationSetWipe(t *testing.T) {
	rs := newTestRotationSet(t)
	first := mustOperator(t)
	second := mustOperator(t)
	firstSeed, _ := first.Seed()
	secondSeed, _ := second.Seed()

	// Keep internal references so we can inspect the stored seed bytes.
	firstStored := append([]byte{}, firstSeed...)
	secondStored := append([]byte{}, secondSeed...)
	if err := rs.ActivateSeedGeneration(append([]byte{}, firstSeed...), 1, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := rs.ActivateSeedGeneration(append([]byte{}, secondSeed...), 2, time.Time{}); err != nil {
		t.Fatal(err)
	}

	// Locate the underlying kp seeds before wiping via the members map.
	rs.mu.RLock()
	stored := make([][]byte, 0, len(rs.members))
	for _, m := range rs.members {
		if k, ok := m.key.(*kp); ok {
			stored = append(stored, k.seed)
		}
	}
	rs.mu.RUnlock()

	rs.Wipe()

	// Wipe randomizes internal seeds then drops them; the captured slices must
	// no longer contain the original seed material.
	for i, s := range stored {
		if bytes.Equal(s, firstStored) || bytes.Equal(s, secondStored) {
			t.Fatalf("stored seed %d still holds original material after Wipe", i)
		}
	}

	snap := rs.Snapshot()
	if !snap.Closed || len(snap.Members) != 0 || snap.Active != "" {
		t.Fatalf("snapshot after wipe = %+v", snap)
	}
	if _, err := rs.Sign([]byte("x")); err != ErrRotationClosed {
		t.Fatalf("Sign after wipe: expected ErrRotationClosed, got %v", err)
	}
	if err := rs.Verify(time.Now(), []byte("x"), nil); err != ErrRotationClosed {
		t.Fatalf("Verify after wipe: expected ErrRotationClosed, got %v", err)
	}
	if err := rs.ActivateGeneration(mustOperator(t), 3, time.Time{}); err != ErrRotationClosed {
		t.Fatalf("Activate after wipe: expected ErrRotationClosed, got %v", err)
	}
	if err := rs.AddVerificationKey(mustPublic(t, mustOperator(t)), time.Time{}); err != ErrRotationClosed {
		t.Fatalf("Add after wipe: expected ErrRotationClosed, got %v", err)
	}
	if err := rs.Revoke("O", time.Now()); err != ErrRotationClosed {
		t.Fatalf("Revoke after wipe: expected ErrRotationClosed, got %v", err)
	}
	if _, err := rs.ActivePublicKey(); err != ErrRotationClosed {
		t.Fatalf("ActivePublicKey after wipe: expected ErrRotationClosed, got %v", err)
	}
	if _, err := rs.ActiveGeneration(); err != ErrRotationClosed {
		t.Fatalf("ActiveGeneration after wipe: expected ErrRotationClosed, got %v", err)
	}
	// Wipe is idempotent.
	rs.Wipe()
}

// TestRotationSetSnapshotExposesNoPrivateMaterial covers requirement 5: the
// snapshot never contains seed or private key contents.
func TestRotationSetSnapshotExposesNoPrivateMaterial(t *testing.T) {
	rs := newTestRotationSet(t)
	signer := mustOperator(t)
	seed, err := signer.Seed()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.ActivateSeedGeneration(append([]byte{}, seed...), 1, time.Time{}); err != nil {
		t.Fatal(err)
	}
	verifier, err := CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.AddVerificationKey(mustPublic(t, verifier), time.Time{}); err != nil {
		t.Fatal(err)
	}

	snap := rs.Snapshot()
	if snap.Active != mustPublic(t, signer) {
		t.Fatalf("unexpected active key %q", snap.Active)
	}
	if len(snap.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(snap.Members))
	}
	var activeCount int
	for _, m := range snap.Members {
		if m.Active {
			activeCount++
		}
		if !strings.HasPrefix(m.PublicKey, "O") {
			t.Fatalf("snapshot member is not an encoded public key: %q", m.PublicKey)
		}
		if strings.Contains(m.PublicKey, string(seed)) {
			t.Fatal("snapshot leaked seed material")
		}
	}
	if activeCount != 1 {
		t.Fatalf("expected exactly one active member, got %d", activeCount)
	}
}

// TestRotationSetRevokeValidation checks revocation boundary rules and that
// revoking the active signer stops issuance.
func TestRotationSetRevokeValidation(t *testing.T) {
	clock := newFakeClock()
	rs, err := NewRotationSet(withClock(clock.now))
	if err != nil {
		t.Fatal(err)
	}
	signer := mustOperator(t)
	t0 := clock.now()
	if err := rs.ActivateGeneration(signer, 1, t0); err != nil {
		t.Fatal(err)
	}
	pub := mustPublic(t, signer)

	if err := rs.Revoke(pub, t0); err != ErrRotationInvalidTimeRange {
		t.Fatalf("revoke at activation: expected ErrRotationInvalidTimeRange, got %v", err)
	}
	if err := rs.Revoke(pub, t0.Add(-time.Second)); err != ErrRotationInvalidTimeRange {
		t.Fatalf("revoke before activation: expected ErrRotationInvalidTimeRange, got %v", err)
	}
	if err := rs.Revoke("OUNKNOWN", t0.Add(time.Second)); err != ErrInvalidPublicKey {
		t.Fatalf("revoke unknown: expected ErrInvalidPublicKey, got %v", err)
	}

	// Zero revocation time means now; advance the clock so it is after the
	// activation instant.
	clock.advance(time.Minute)
	if err := rs.Revoke(pub, time.Time{}); err != nil {
		t.Fatalf("revoke now: %v", err)
	}
	if _, err := rs.ActivePublicKey(); err != ErrRotationNoActive {
		t.Fatalf("revoked signer still reported active: %v", err)
	}
	if _, err := rs.Sign([]byte("x")); err != ErrRotationNoActive {
		t.Fatalf("sign after revoke: expected ErrRotationNoActive, got %v", err)
	}
}

// TestRotationSetOptions validates option parsing.
func TestRotationSetOptions(t *testing.T) {
	if _, err := NewRotationSet(WithClockSkew(-time.Second)); err != ErrRotationInvalidSkew {
		t.Fatalf("negative skew: expected ErrRotationInvalidSkew, got %v", err)
	}
	if _, err := NewRotationSet(WithRevocationPolicy(RevocationPolicy(99))); err != ErrRotationInvalidPolicy {
		t.Fatalf("bad policy: expected ErrRotationInvalidPolicy, got %v", err)
	}
	rs, err := NewRotationSet(WithClockSkew(time.Second), WithRevocationPolicy(GracePeriodRevoked))
	if err != nil {
		t.Fatal(err)
	}
	snap := rs.Snapshot()
	if snap.Skew != time.Second || snap.Policy != GracePeriodRevoked {
		t.Fatalf("options not applied: %+v", snap)
	}
}

// TestRotationSetEdgeCases covers defensive branches: nil keys, signing once
// the active slot is cleared, and generation queries without an active member.
func TestRotationSetEdgeCases(t *testing.T) {
	rs := newTestRotationSet(t)

	if err := rs.ActivateGeneration(nil, 1, time.Time{}); err != ErrInvalidKey {
		t.Fatalf("nil key: expected ErrInvalidKey, got %v", err)
	}

	signer := mustOperator(t)
	if err := rs.ActivateGeneration(signer, 7, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if gen, err := rs.ActiveGeneration(); err != nil || gen != 7 {
		t.Fatalf("ActiveGeneration = %d, %v; want 7", gen, err)
	}

	// Revoking the active signer clears the slot and blocks further signing.
	if err := rs.Revoke(mustPublic(t, signer), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.Sign([]byte("x")); err != ErrRotationNoActive {
		t.Fatalf("Sign after active revoked: expected ErrRotationNoActive, got %v", err)
	}
	if _, err := rs.ActiveGeneration(); err != ErrRotationNoActive {
		t.Fatalf("ActiveGeneration after revoke: expected ErrRotationNoActive, got %v", err)
	}
}

// TestRotationSetPromotesVerificationMember ensures a verification key can be
// promoted to active when its seed-backed KeyPair is supplied.
func TestRotationSetPromotesVerificationMember(t *testing.T) {
	rs := newTestRotationSet(t)
	signer := mustOperator(t)
	pub := mustPublic(t, signer)
	if err := rs.AddVerificationKey(pub, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.ActivePublicKey(); err != ErrRotationNoActive {
		t.Fatal(err)
	}
	if err := rs.ActivateGeneration(signer, 1, time.Time{}); err != nil {
		t.Fatalf("promotion failed: %v", err)
	}
	if got, _ := rs.ActivePublicKey(); got != pub {
		t.Fatalf("promoted key is not active")
	}
	if len(rs.Snapshot().Members) != 1 {
		t.Fatal("promotion must not duplicate the member")
	}
	sig, err := rs.Sign([]byte("data"))
	if err != nil {
		t.Fatalf("Sign after promotion: %v", err)
	}
	if err := rs.Verify(time.Now(), []byte("data"), sig); err != nil {
		t.Fatalf("Verify after promotion: %v", err)
	}
}
