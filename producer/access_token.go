package producer

import (
	"net/http"
	"time"
	"io/ioutil"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"github.com/mitchellh/mapstructure"

	"github.com/free5gc/http_wrapper"
	nrf_context "github.com/free5gc/nrf/context"
	"github.com/free5gc/nrf/logger"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/MongoDBLibrary"
)

func HandleAccessTokenRequest(request *http_wrapper.Request) *http_wrapper.Response {
	// Param of AccessTokenRsp
	logger.AccessTokenLog.Infoln("Handle AccessTokenRequest")

	accessTokenReq := request.Body.(models.AccessTokenReq)

	response, errResponse := AccessTokenProcedure(accessTokenReq)

	if response != nil {
		// status code is based on SPEC, and option headers
		return http_wrapper.NewResponse(http.StatusOK, nil, response)
	} else if errResponse != nil {
		return http_wrapper.NewResponse(http.StatusBadRequest, nil, errResponse)
	}
	problemDetails := &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func AccessTokenProcedure(request models.AccessTokenReq) (response *models.AccessTokenRsp,
	errResponse *models.AccessTokenErr) {
	logger.AccessTokenLog.Infoln("In AccessTokenProcedure")

	var expiration int32 = 1000
	scope := request.Scope
	tokenType := "Bearer"
	now := int32(time.Now().Unix())

	errResponse = AccessTokenScopeCheck(request)
	if errResponse != nil {
		return nil, errResponse
	}

	// Create AccessToken
	accessTokenClaims := models.AccessTokenClaims{
		Iss:            nrf_context.Nrf_NfInstanceID, // TODO: NF instance id of the NRF
		Sub:            request.NfInstanceId,         // nfInstanceId of service consumer
		Aud:            request.TargetNfInstanceId,   // nfInstanceId of service producer
		Scope:          request.Scope,                // TODO: the name of the NF services for which the
		Exp:            now + expiration,             // access_token is authorized for use
		StandardClaims: jwt.StandardClaims{},
	}
	accessTokenClaims.IssuedAt = int64(now)

	// Use RSA as a signing method
	privKeyPath := "../support/TLS/nrf.key"
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		logger.AccessTokenLog.Warnln("SigningBytes error: ", err)
		errResponse = &models.AccessTokenErr{
			Error:  "UNSPECIFIED",
		}

		return nil, errResponse
	}
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		logger.AccessTokenLog.Warnln("SigningKey error: ", err)
		errResponse = &models.AccessTokenErr{
			Error:  "UNSPECIFIED",
		}

		return nil, errResponse
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS512"), accessTokenClaims)
	accessToken, err := token.SignedString(signKey)

	if err != nil {
		logger.AccessTokenLog.Warnln("Signed string error: ", err)
		errResponse = &models.AccessTokenErr{
			Error:  "UNSPECIFIED",
		}

		return nil, errResponse
	}

	response = &models.AccessTokenRsp{
		AccessToken: accessToken,
		TokenType:   tokenType,
		ExpiresIn:   expiration,
		Scope:       scope,
	}

	return response, nil
}

func AccessTokenScopeCheck(req models.AccessTokenReq) (errResponse *models.AccessTokenErr) {
	collName := "NfProfile"
	reqGrantType := req.GrantType
	reqNfType := strings.ToUpper(string(req.NfType))
	reqTargetNfType := strings.ToUpper(string(req.TargetNfType))
	reqNfInstanceId := req.NfInstanceId

	if reqGrantType != "client_credentials" {
		errResponse = &models.AccessTokenErr{
			Error:  "unsupported_grant_type",
		}
		return errResponse
	}

	if reqNfType == "" || reqTargetNfType == "" || reqNfInstanceId == "" {
		errResponse = &models.AccessTokenErr{
			Error:  "invalid_request",
		}
		return errResponse
	}

	filter := bson.M{"nfInstanceId": reqNfInstanceId}
	nfInfo := MongoDBLibrary.RestfulAPIGetOne(collName, filter)
	var nfProfile = models.NfProfile{}
	mapstructure.Decode(nfInfo, &nfProfile)
	if strings.ToUpper(string(nfProfile.NfType)) != reqNfType {
		errResponse = &models.AccessTokenErr{
			Error:  "invalid_client",
		}
		return errResponse
	}

	filter = bson.M{"nfType": reqNfType}
	nfInfo = MongoDBLibrary.RestfulAPIGetOne(collName, filter)
	nfProfile = models.NfProfile{}
	mapstructure.Decode(nfInfo, &nfProfile)
	nfServices := *nfProfile.NfServices

	scopes := strings.Split(req.Scope, " ")

	for _, reqNfService := range scopes {
		var nfService models.NfService
		var found bool = false

		for _, nfService = range nfServices {
			if string(nfService.ServiceName) == reqNfService {
				for _, nfType := range nfService.AllowedNfTypes {
					if string(nfType) == reqNfType {
						found = true
						break
					}
				}
				break
			}
		}
		if found == false {
			errResponse = &models.AccessTokenErr{
				Error:  "invalid_scope",
			}
			return errResponse
		}
	}

	return nil
}
