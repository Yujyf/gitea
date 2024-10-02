package setting

var BKAuthClient = struct {
	BKAuthEnabled  bool
	BKPaasLoginUrl string
}{
	BKAuthEnabled:  false,
	BKPaasLoginUrl: "http://example.com/login",
}

func loadBKAuth(rootCfg ConfigProvider) {
	sec := rootCfg.Section("blueking")
	BKAuthClient.BKAuthEnabled = sec.Key("BK_AUTH_ENABLED").MustBool()
	BKAuthClient.BKPaasLoginUrl = sec.Key("BKPAAS_LOGIN_URL").String()
}
