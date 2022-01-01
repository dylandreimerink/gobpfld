package kernelsupport

import "testing"

func Test_kernelVersion_Higher(t *testing.T) {
	tests := []struct {
		name string
		a    KernelVersion
		b    KernelVersion
		want bool
	}{
		{
			name: "2.0.0 >= 1.0.0 - major",
			a:    KernelVersion{Major: 2},
			b:    KernelVersion{Major: 1},
			want: true,
		},
		{
			name: "2.1.0 >= 2.0.0 - minor",
			a:    KernelVersion{Major: 2, Minor: 1},
			b:    KernelVersion{Major: 2},
			want: true,
		},
		{
			name: "2.1.1 >= 2.1.0 - patch",
			a:    KernelVersion{Major: 2, Minor: 1, Patch: 1},
			b:    KernelVersion{Major: 2, Minor: 1},
			want: true,
		},
		{
			name: "2.2.2 >= 2.2.2 - exact",
			a:    KernelVersion{Major: 2, Minor: 2, Patch: 2},
			b:    KernelVersion{Major: 2, Minor: 2, Patch: 2},
			want: true,
		},
		{
			name: "1.1.0 >= 2.0.0 - major false",
			a:    KernelVersion{Major: 1, Minor: 1},
			b:    KernelVersion{Major: 2},
			want: false,
		},
		{
			name: "2.1.0 >= 2.2.0 - minor false",
			a:    KernelVersion{Major: 2, Minor: 1},
			b:    KernelVersion{Major: 2, Minor: 2},
			want: false,
		},
		{
			name: "2.2.0 >= 2.2.2 - patch false",
			a:    KernelVersion{Major: 2, Minor: 2},
			b:    KernelVersion{Major: 2, Minor: 2, Patch: 1},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Higher(tt.b); got != tt.want {
				t.Errorf("kernelVersion.Higher() = %v, want %v", got, tt.want)
			}
		})
	}
}
