package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"reflect"
	"test/accesstoken"
	"test/gothrift/iuct_service/iuct_client"
	"test/playtoken"
)

type UID = int64
type USER_ID int64

func init() {
	go func() {
		http.ListenAndServe(":38000", nil)
	}()
}

func main() {
	test_type()
	accesstoken_test()
	rpcTest()
	playtokenTest()
}

func test_type() {
	var iuser int64 = 50000001
	var uuser UID = 0
	var suser USER_ID = 0
	fmt.Println("iuser:", reflect.TypeOf(iuser))
	fmt.Println("uuser:", reflect.TypeOf(uuser))
	fmt.Println("suser:", reflect.TypeOf(suser))
	uuser = iuser
	//suser = iuser
}

func accesstoken_test() {
	//R621B3CC2U1096A06AK3B9ACB03IBB17A8C0P8M2FAF72AV20002Z6B725W16D798CCC0A517EE
	//TOKEN1000084ID111111
	//P1869FK45748C07T621BA1F8
	ret, stToken := accesstoken.GetAccountTokenInfo("R621B3CC2U1096A06AK3B9ACB03IBB17A8C0P8M2FAF72AV20002Z6B725W16D798CCC0A517EE")
	fmt.Println(ret)
	fmt.Printf("token=%+v\n", stToken)

	var uid UID = 1
	var uid1 int64 = 2
	var uids []int64
	fmt.Println(reflect.TypeOf(uid))
	fmt.Println(reflect.TypeOf(uid1))
	if reflect.TypeOf(uid) == reflect.TypeOf(uid1) {
		fmt.Println("==")
	} else {
		fmt.Println("!=")
	}
	uids = append(uids, uid)
	uids = append(uids, uid1)
	fmt.Println(uids)
}

func rpcTest() {
	iuct_client.RPCGetProgramHits(100000006)
}

func playtokenTest() {
	playtoken.CppTest(true)
	playtoken.BentchCppTest(1000000000)
}
