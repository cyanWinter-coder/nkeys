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
	"sort"
	"sync"
	"time"
)

// RevocationPolicy decides how signatures from a revoked key are treated when
// the message time still falls within the allowed clock skew of the revocation.
type RevocationPolicy int

const (
	// RejectRevoked rejects every signature made by a revoked member, even when
	// the message time is within the clock skew allowance of the revocation time.
	RejectRevoked RevocationPolicy = iota

	// GracePeriodRevoked accepts signatures from a revoked member while the
	// message time is at or after the revocation time but no later than the
	// configured clock skew allowance after it. This covers credentials issued
	// just before revocation by a signer with a slow clock. Once the grace
	// window has elapsed, signatures from the revoked member are rejected.
	GracePeriodRevoked
)

// rotationMember is a single key inside a RotationSet. KeyPair encoding is the
// existing nkeys encoding; members holding a seed can sign, public-key-only
// members can only verify.
type rotationMember struct {
	key         KeyPair
	public      string
	generation  uint64
	activatedAt time.Time
	revokedAt   time.Time // zero means not revoked
}

// validAt reports whether the member was active at the message time.
func (m *rotationMember) validAt(at time.Time) bool {
	if !m.activatedAt.IsZero() && at.Before(m.activatedAt) {
		return false
	}
	if !m.revokedAt.IsZero() && !at.Before(m.revokedAt) {
		return false
	}
	return true
}

// RotationSet is a key rotation collection with an overlap window. It holds one
// active signing key at a time and any number of verification keys. Each member
// carries activation and revocation instants, so verification can select the
// member that was valid at the message time rather than whatever is current.
//
// A RotationSet is safe for concurrent use.
type RotationSet struct {
	mu            sync.RWMutex
	members       map[string]*rotationMember
	active        string // encoded public key of the active signing member, "" when none
	maxGeneration uint64 // highest generation ever activated; prevents rollback
	skew          time.Duration
	policy        RevocationPolicy
	now           func() time.Time
	closed        bool
}

// RotationOption configures a RotationSet at construction.
type RotationOption func(*RotationSet) error

// WithClockSkew sets the maximum clock skew applied when evaluating signatures
// near a member's revocation time. It must be non-negative.
func WithClockSkew(skew time.Duration) RotationOption {
	return func(rs *RotationSet) error {
		if skew < 0 {
			return ErrRotationInvalidSkew
		}
		rs.skew = skew
		return nil
	}
}

// WithRevocationPolicy selects the policy for signatures from revoked members
// whose message time falls within the clock skew allowance after the
// revocation. Defaults to RejectRevoked.
func WithRevocationPolicy(policy RevocationPolicy) RotationOption {
	return func(rs *RotationSet) error {
		switch policy {
		case RejectRevoked, GracePeriodRevoked:
		default:
			return ErrRotationInvalidPolicy
		}
		rs.policy = policy
		return nil
	}
}

// withClock overrides the time source. It is unexported and used by tests.
func withClock(now func() time.Time) RotationOption {
	return func(rs *RotationSet) error {
		rs.now = now
		return nil
	}
}

// NewRotationSet creates an empty rotation set.
func NewRotationSet(opts ...RotationOption) (*RotationSet, error) {
	rs := &RotationSet{
		members: make(map[string]*rotationMember),
		policy:  RejectRevoked,
		now:     time.Now,
	}
	for _, opt := range opts {
		if err := opt(rs); err != nil {
			return nil, err
		}
	}
	return rs, nil
}

// checkMemberKey validates a candidate key and returns its encoded public key.
// It runs the existing seed checks and public key length/small-order defenses
// via FromSeed, FromPublicKey and PublicKey. Curve keys are rejected because a
// rotation set performs Ed25519 signing and verification.
func checkMemberKey(kp KeyPair) (string, PrefixByte, error) {
	if kp == nil {
		return "", PrefixByteUnknown, ErrInvalidKey
	}
	public, err := kp.PublicKey()
	if err != nil {
		return "", PrefixByteUnknown, err
	}
	prefix, _, err := decodePublicKey(public)
	if err != nil {
		return "", PrefixByteUnknown, err
	}
	if prefix == PrefixByteCurve {
		return "", PrefixByteUnknown, ErrInvalidCurveKeyOperation
	}
	return public, prefix, nil
}

// AddVerificationKey adds a public-key-only verification member. The member is
// valid for message times at or after activatedAt; a zero activatedAt means the
// member is immediately valid. The key's prefix must match the prefix already
// in use by the set.
func (rs *RotationSet) AddVerificationKey(public string, activatedAt time.Time) error {
	kp, err := FromPublicKey(public)
	if err != nil {
		return err
	}
	encoded, prefix, err := checkMemberKey(kp)
	if err != nil {
		return err
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.closed {
		return ErrRotationClosed
	}
	if err := rs.checkPrefixLocked(prefix); err != nil {
		return err
	}
	if _, exists := rs.members[encoded]; exists {
		return ErrRotationMemberExists
	}
	rs.members[encoded] = &rotationMember{
		key:         kp,
		public:      encoded,
		activatedAt: activatedAt,
	}
	return nil
}

// checkPrefixLocked ensures all members share one key role.
func (rs *RotationSet) checkPrefixLocked(prefix PrefixByte) error {
	for _, m := range rs.members {
		if Prefix(m.public) != prefix {
			return ErrIncompatibleKey
		}
		break
	}
	return nil
}

// ActivateGeneration makes kp the active signing key for the given generation.
// The previously active key stays in the set as a verification key so that
// credentials issued before the rotation remain verifiable during the overlap
// window.
//
// Generations are strictly monotonic: the same generation may only be activated
// once across the set, and a generation lower than one already activated is a
// rollback. All members of the set must share a key prefix.
func (rs *RotationSet) ActivateGeneration(kp KeyPair, generation uint64, activatedAt time.Time) error {
	encoded, prefix, err := checkMemberKey(kp)
	if err != nil {
		return err
	}
	// The active member must hold a private key, otherwise it cannot sign.
	if _, err := kp.Seed(); err != nil {
		return ErrCannotSign
	}
	if generation == 0 {
		return ErrRotationInvalidGeneration
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.closed {
		return ErrRotationClosed
	}
	if err := rs.checkPrefixLocked(prefix); err != nil {
		return err
	}
	if generation <= rs.maxGeneration {
		if generation == rs.maxGeneration {
			return ErrRotationGenerationConflict
		}
		return ErrRotationGenerationRollback
	}
	if rs.active == encoded {
		return ErrRotationMemberExists
	}

	if existing, ok := rs.members[encoded]; ok {
		// Promoting a verification member: it becomes the active signer.
		existing.key = kp
		existing.generation = generation
		existing.activatedAt = activatedAt
	} else {
		rs.members[encoded] = &rotationMember{
			key:         kp,
			public:      encoded,
			generation:  generation,
			activatedAt: activatedAt,
		}
	}
	rs.active = encoded
	rs.maxGeneration = generation
	return nil
}

// ActivateSeedGeneration migrates a raw nkey seed into the set as the active
// signing key for the given generation. On any failure the set does not change
// and every seed byte handled by this call is replaced with zeros, including
// the caller's seed buffer: callers must not reuse the buffer after a failed
// migration. On success the buffer is left untouched so callers remain owners
// of their seed material.
func (rs *RotationSet) ActivateSeedGeneration(seed []byte, generation uint64, activatedAt time.Time) (err error) {
	kp, err := FromSeed(seed)
	if err != nil {
		// FromSeed rejected the seed before copying; clear the caller's buffer
		// anyway so a failed migration never leaves handled seed material behind.
		zeroize(seed)
		return err
	}
	defer func() {
		if err != nil {
			zeroize(seed)
			kp.Wipe()
		}
	}()
	return rs.ActivateGeneration(kp, generation, activatedAt)
}

// Sign signs input with the active private key. Signing with a verification-only
// member or after the active key has been revoked is not possible.
func (rs *RotationSet) Sign(input []byte) ([]byte, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if rs.closed {
		return nil, ErrRotationClosed
	}
	if rs.active == "" {
		return nil, ErrRotationNoActive
	}
	active := rs.members[rs.active]
	if !active.revokedAt.IsZero() {
		return nil, ErrCannotSign
	}
	return active.key.Sign(input)
}

// Verify verifies a signature against the member that was valid at the message
// time at. It never selects a member based solely on the current set contents:
// members whose activation is in the future or whose revocation is in the past
// relative to at are skipped.
func (rs *RotationSet) Verify(at time.Time, input, sig []byte) error {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if rs.closed {
		return ErrRotationClosed
	}

	candidates := make([]*rotationMember, 0, len(rs.members))
	for _, m := range rs.members {
		if m.validAt(at) {
			candidates = append(candidates, m)
			continue
		}
		// The member is not valid at the message time. When this is because it
		// was revoked at or before at, the grace policy may still accept the
		// credential: a signer running a slow clock can have issued it before
		// the revocation while stamping a time up to skew after it.
		if !m.revokedAt.IsZero() && rs.policy == GracePeriodRevoked &&
			at.Before(m.revokedAt.Add(rs.skew)) {
			candidates = append(candidates, m)
		}
	}
	if len(candidates) == 0 {
		return ErrRotationNoValidMember
	}

	var lastErr error
	for _, m := range candidates {
		if err := m.key.Verify(input, sig); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return ErrInvalidSignature
}

// Revoke marks the member identified by public revokedAt. A zero revokedAt is
// replaced with the current time. Revoking the active signer also clears the
// active slot, so no new signatures can be issued with it.
func (rs *RotationSet) Revoke(public string, revokedAt time.Time) error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.closed {
		return ErrRotationClosed
	}
	m, ok := rs.members[public]
	if !ok {
		return ErrInvalidPublicKey
	}
	if revokedAt.IsZero() {
		revokedAt = rs.now()
	}
	if !m.activatedAt.IsZero() && !revokedAt.After(m.activatedAt) {
		return ErrRotationInvalidTimeRange
	}
	m.revokedAt = revokedAt
	if rs.active == public {
		rs.active = ""
	}
	return nil
}

// ActivePublicKey returns the encoded public key of the current active signing
// member, or ErrRotationNoActive when none is active.
func (rs *RotationSet) ActivePublicKey() (string, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if rs.closed {
		return "", ErrRotationClosed
	}
	if rs.active == "" {
		return "", ErrRotationNoActive
	}
	return rs.active, nil
}

// ActiveGeneration returns the generation of the current active signing member,
// or ErrRotationNoActive when none is active.
func (rs *RotationSet) ActiveGeneration() (uint64, error) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	if rs.closed {
		return 0, ErrRotationClosed
	}
	if rs.active == "" {
		return 0, ErrRotationNoActive
	}
	return rs.members[rs.active].generation, nil
}

// RotationMemberSnapshot describes one member without exposing any seed or
// private key material.
type RotationMemberSnapshot struct {
	PublicKey   string
	Generation  uint64
	Active      bool
	ActivatedAt time.Time
	RevokedAt   time.Time
}

// RotationSnapshot is a private-material-free view of a RotationSet.
type RotationSnapshot struct {
	Active  string
	Skew    time.Duration
	Policy  RevocationPolicy
	Closed  bool
	Members []RotationMemberSnapshot
}

// Snapshot returns a point-in-time view of the set. It contains encoded public
// keys and timing metadata only; seeds and private keys are never included.
func (rs *RotationSet) Snapshot() RotationSnapshot {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	snap := RotationSnapshot{
		Active:  rs.active,
		Skew:    rs.skew,
		Policy:  rs.policy,
		Closed:  rs.closed,
		Members: make([]RotationMemberSnapshot, 0, len(rs.members)),
	}
	for _, m := range rs.members {
		snap.Members = append(snap.Members, RotationMemberSnapshot{
			PublicKey:   m.public,
			Generation:  m.generation,
			Active:      m.public == rs.active,
			ActivatedAt: m.activatedAt,
			RevokedAt:   m.revokedAt,
		})
	}
	sort.Slice(snap.Members, func(i, j int) bool {
		if snap.Members[i].Generation != snap.Members[j].Generation {
			return snap.Members[i].Generation < snap.Members[j].Generation
		}
		if !snap.Members[i].ActivatedAt.Equal(snap.Members[j].ActivatedAt) {
			return snap.Members[i].ActivatedAt.Before(snap.Members[j].ActivatedAt)
		}
		return snap.Members[i].PublicKey < snap.Members[j].PublicKey
	})
	return snap
}

// Wipe closes the set and replaces every held seed with zeros, then drops all
// members. After Wipe the set is closed and every operation returns
// ErrRotationClosed.
func (rs *RotationSet) Wipe() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, m := range rs.members {
		m.key.Wipe()
	}
	rs.members = make(map[string]*rotationMember)
	rs.active = ""
	rs.maxGeneration = 0
	rs.closed = true
}

// zeroize replaces every byte of b with zeros. Unlike kp.Wipe, which
// randomizes stored seeds, this deterministically clears transient seed buffers
// handled on failed migration paths.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
