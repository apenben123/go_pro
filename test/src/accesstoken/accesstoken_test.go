package accesstoken

import (
	"fmt"
	"testing"
)

func TestTestToken(t *testing.T) {
	token := "TOKEN1000084ID111111"
	fmt.Printf("accesstoken=%s\n", token)
	ret, stToken := GetAccountTokenInfo(token)
	fmt.Printf("ret=%d, token=%+v\n", ret, stToken)
}

func TestAdminToken(t *testing.T) {
	token := "P1869FK45748C07T621BA1F8"
	fmt.Printf("accesstoken=%s\n", token)
	ret, stToken := GetAccountTokenInfo(token)
	fmt.Printf("ret=%d, token=%+v\n", ret, stToken)
}

func TestAccessToken(t *testing.T) {
	token := "R621B3CC2U1096A06AK3B9ACB03IBB17A8C0P8M2FAF72AV20002Z6B725W16D798CCC0A517EE"
	fmt.Printf("accesstoken=%s\n", token)
	ret, stToken := GetAccountTokenInfo(token)
	fmt.Printf("ret=%d, token=%+v\n", ret, stToken)
}
