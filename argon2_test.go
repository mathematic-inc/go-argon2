package argon2

import (
	"testing"
)

func TestCompareHashAndPassword(t *testing.T) {
	type args struct {
		hashedPassword []byte
		password       []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty-password",
			args: args{
				hashedPassword: []byte("$argon2id$v=19$m=65536,t=1,p=6$KTAymECXXnekfa8FcES/Su$KPcCEYfGqeQbFwXKB1RsMQsrqgU1VJN65em0MREh0IS"),
				password:       []byte(""),
			},
		},
		{
			name: "non-empty-password",
			args: args{
				hashedPassword: []byte("$argon2id$v=19$m=65536,t=1,p=6$KTAymECXXnekfa8FcES/Su$KPcCEYfGqeQbFwXKB1RsMQsrqgU1VJN65em0MREh0IS"),
				password:       []byte("f"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CompareHashAndPassword(tt.args.hashedPassword, tt.args.password); (err != nil) != tt.wantErr {
				t.Errorf("CompareHashAndPassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
