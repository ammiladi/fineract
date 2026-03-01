/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.fineract.infrastructure.security.config;

import java.util.List;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;

/**
 * JwtDecoder that accepts JWTs from multiple issuers (e.g. multiple Keycloak realms). Tries each issuer's decoder in
 * order until one successfully decodes and validates the token.
 */
public class MultiIssuerJwtDecoder implements JwtDecoder {

    private final List<JwtDecoder> decoders;

    public MultiIssuerJwtDecoder(List<String> issuerUris) {
        this.decoders = issuerUris.stream().map(JwtDecoders::fromIssuerLocation).toList();
    }

    @Override
    public Jwt decode(String token) throws OAuth2AuthenticationException {
        OAuth2AuthenticationException lastException = null;
        for (JwtDecoder decoder : decoders) {
            try {
                return decoder.decode(token);
            } catch (OAuth2AuthenticationException e) {
                lastException = e;
            }
        }
        throw lastException != null ? lastException : new OAuth2AuthenticationException(null, "No decoder could validate the token.");
    }
}
