package agent

import (
	"testing"

	"openpak/np-matching2/wire"
)

func TestMarkOwner(t *testing.T) {
	ms := []wire.MemberInfo{{No: 3}, {No: 2}}
	markOwner(ms)
	if ms[0].Owner || !ms[1].Owner {
		t.Fatalf("lowest not owner: %+v", ms)
	}
	ms = []wire.MemberInfo{{No: 1}, {No: 2, Owner: true}}
	markOwner(ms)
	if ms[0].Owner {
		t.Fatalf("core owner overridden: %+v", ms)
	}
}
