package producer

import (
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"github.com/free5gc/http_wrapper"
	"github.com/free5gc/nrf/logger"
)

type AccessTokenClaims struct {
	Iss   string // TODO: NF instance id of the NRF
	Sub   string // nfInstanceId of service consumer
	Aud   string // nfInstanceId of service producer
	Scope string // TODO: the name of the NF services for which the
	Exp   int32  // access_token is authorized for use
	*jwt.StandardClaims
}

func OAuthVerify(request *http_wrapper.Request, serviceName string, pubKeyPath string) *http_wrapper.Response {
	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		logger.ManagementLog.Infoln("VerifyBytes failed")
		return http_wrapper.NewResponse(http.StatusBadRequest, nil, err)
	}
	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		logger.ManagementLog.Infoln("VerifyKey failed")
		return http_wrapper.NewResponse(http.StatusBadRequest, nil, err)
	}
	auth := strings.Split(request.Header["Authorization"][0], " ")
	tokenString := strings.TrimSpace(auth[1])
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		logger.ManagementLog.Infoln(err.Error())
		return http_wrapper.NewResponse(http.StatusUnauthorized, nil, err)
	}

	if !VerifyScope(token.Claims.(*AccessTokenClaims).Scope, serviceName) {
		return http_wrapper.NewResponse(http.StatusForbidden, nil, nil)
	}
	return nil
}

func VerifyScope(scope string, serviceName string) bool {
	return strings.Contains(scope, serviceName)
}
