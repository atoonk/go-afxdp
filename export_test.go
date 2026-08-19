//go:build linux

package afxdp

// Bridges for the external test package (afxdp_test), for internals that are
// deliberately not public. MatchPacket is public; these are not.

// BuildFilterProgramFrags loads a filter program with BPF_F_XDP_HAS_FRAGS set
// and immediately closes it, returning only the load error. This is the same
// assembly path Open uses.
func BuildFilterProgramFrags(maxQueues int, exceptions, matches []Match) error {
	p, err := newFilterProgram(maxQueues, exceptions, matches, true)
	if err != nil {
		return err
	}
	p.Close()
	return nil
}

// NewVethPair creates an up veth pair that is removed when the test ends, so
// external tests can exercise the real Open path.
var NewVethPair = newVethPair
