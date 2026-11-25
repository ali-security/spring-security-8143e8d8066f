/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.preauth.x509;

import java.security.cert.X509Certificate;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.util.FieldUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests the default principal extraction performed by {@link X509AuthenticationFilter}.
 *
 * @author Luke Taylor
 */
public class X509AuthenticationFilterTests {
    private final X509AuthenticationFilter filter = new X509AuthenticationFilter();

    @Test
    public void defaultPrincipalExtractorIsSubjectX500PrincipalExtractor() throws Exception {
        Object principalExtractor = FieldUtils.getFieldValue(filter, "principalExtractor");
        assertTrue(principalExtractor instanceof SubjectX500PrincipalExtractor);
    }

    // gh-19254
    @Test
    public void defaultExtractorIgnoresLessSpecificCn() throws Exception {
        Object principal = extractPrincipal(X509TestUtils.buildTestCertificateWithMultipleCns());
        assertEquals("alice", principal);
    }

    // gh-19254
    @Test
    public void defaultExtractorIgnoresCnEmbeddedInAnotherAttribute() throws Exception {
        Object principal = extractPrincipal(X509TestUtils.buildTestCertficateWithEmbeddedDn());
        assertEquals("luke", principal);
    }

    @Test
    public void defaultExtractorReturnsCnFromStandardCertificate() throws Exception {
        Object principal = extractPrincipal(X509TestUtils.buildTestCertificate());
        assertEquals("Luke Taylor", principal);
    }

    @Test
    public void nullPrincipalIsReturnedWhenNoCertificateInRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertNull(filter.getPreAuthenticatedPrincipal(request));
    }

    private Object extractPrincipal(X509Certificate cert) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute("javax.servlet.request.X509Certificate", new X509Certificate[] {cert});

        return filter.getPreAuthenticatedPrincipal(request);
    }
}
