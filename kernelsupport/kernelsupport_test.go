package kernelsupport

import "testing"

func Test_kernelVersion_Higher(t *testing.T) {
	tests := []struct {
		name string
		a    kernelVersion
		b    kernelVersion
		want bool
	}{
		{
			name: "2.0.0 >= 1.0.0 - major",
			a:    kernelVersion{major: 2},
			b:    kernelVersion{major: 1},
			want: true,
		},
		{
			name: "2.1.0 >= 2.0.0 - minor",
			a:    kernelVersion{major: 2, minor: 1},
			b:    kernelVersion{major: 2},
			want: true,
		},
		{
			name: "2.1.1 >= 2.1.0 - patch",
			a:    kernelVersion{major: 2, minor: 1, patch: 1},
			b:    kernelVersion{major: 2, minor: 1},
			want: true,
		},
		{
			name: "2.2.2 >= 2.2.2 - exact",
			a:    kernelVersion{major: 2, minor: 2, patch: 2},
			b:    kernelVersion{major: 2, minor: 2, patch: 2},
			want: true,
		},
		{
			name: "1.1.0 >= 2.0.0 - major false",
			a:    kernelVersion{major: 1, minor: 1},
			b:    kernelVersion{major: 2},
			want: false,
		},
		{
			name: "2.1.0 >= 2.2.0 - minor false",
			a:    kernelVersion{major: 2, minor: 1},
			b:    kernelVersion{major: 2, minor: 2},
			want: false,
		},
		{
			name: "2.2.0 >= 2.2.2 - patch false",
			a:    kernelVersion{major: 2, minor: 2},
			b:    kernelVersion{major: 2, minor: 2, patch: 1},
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
