// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

func getKeyAuditOrganization(key *object.Key) string {
	if key == nil {
		return "built-in"
	}
	if key.Organization != "" {
		return key.Organization
	}
	if key.Application != "" {
		application, err := object.GetApplication(util.GetId("admin", key.Application))
		if err == nil && application != nil && application.Organization != "" {
			return application.Organization
		}
	}
	if key.Owner != "" {
		return key.Owner
	}
	return "built-in"
}

func getKeyAuditPayload(key *object.Key, result string) map[string]string {
	payload := map[string]string{
		"keyId":        "",
		"keyType":      "",
		"organization": "",
		"application":  "",
		"result":       result,
	}
	if key == nil {
		return payload
	}

	payload["keyId"] = key.GetId()
	payload["keyType"] = key.Type
	payload["organization"] = getKeyAuditOrganization(key)
	payload["application"] = key.Application
	return payload
}

func (c *ApiController) addKeyAuditRecord(action string, key *object.Key, result string, response string) {
	record := &object.Record{
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: getKeyAuditOrganization(key),
		User:         "",
		ClientIp:     strings.Replace(util.GetClientIpFromRequest(c.Ctx.Request), ": ", "", -1),
		Method:       c.Ctx.Request.Method,
		RequestUri:   c.Ctx.Request.URL.Path,
		Action:       action,
		Language:     c.GetAcceptLanguage(),
		Object:       util.StructToJson(getKeyAuditPayload(key, result)),
		Response:     response,
		StatusCode:   200,
	}
	if key != nil {
		record.User = key.User
	}

	util.SafeGoroutine(func() {
		object.AddRecord(record)
	})
}

func (c *ApiController) addApiKeyGrantRecord(apiKey string, result string, response string) {
	key, err := object.GetKeyBySecret(apiKey)
	if err != nil {
		return
	}
	if result == "success" && key != nil {
		_, _ = object.UpdateKeyLastUsedTime(key.GetId())
	}

	record := &object.Record{
		Name:         util.GenerateId(),
		CreatedTime:  util.GetCurrentTime(),
		Organization: getKeyAuditOrganization(key),
		User:         "",
		ClientIp:     strings.Replace(util.GetClientIpFromRequest(c.Ctx.Request), ": ", "", -1),
		Method:       c.Ctx.Request.Method,
		RequestUri:   c.Ctx.Request.URL.Path,
		Action:       "grant-api-key",
		Language:     c.GetAcceptLanguage(),
		Object:       util.StructToJson(getKeyAuditPayload(key, result)),
		Response:     fmt.Sprintf("{status:\"%s\", msg:\"%s\"}", result, response),
		StatusCode:   200,
	}
	if key != nil {
		record.User = key.User
	}

	util.SafeGoroutine(func() {
		object.AddRecord(record)
	})
}
