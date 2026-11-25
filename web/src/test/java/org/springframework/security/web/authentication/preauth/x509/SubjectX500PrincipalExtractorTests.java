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

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Tests for {@link SubjectX500PrincipalExtractor}.
 *
 * @author Max Batischev
 */
public class SubjectX500PrincipalExtractorTests {

    private final SubjectX500PrincipalExtractor extractor = new SubjectX500PrincipalExtractor();

    @Test
    public void extractWhenCnPatternSetThenExtractsPrincipalName() throws Exception {
        Object principal = this.extractor.extractPrincipal(X509TestUtils.buildTestCertificate());

        assertEquals("Luke Taylor", principal);
    }

    @Test
    public void extractWhenEmailPatternSetThenExtractsPrincipalName() throws Exception {
        this.extractor.setExtractPrincipalNameFromEmail(true);

        Object principal = this.extractor.extractPrincipal(X509TestUtils.buildTestCertificate());

        assertEquals("luke@monkeymachine", principal);
    }

    @Test
    public void extractWhenCnAtEndThenExtractsPrincipalName() throws Exception {
        Object principal = this.extractor.extractPrincipal(X509TestUtils.buildTestCertificateWithCnAtEnd());

        assertEquals("Duke", principal);
    }

    @Test
    public void extractWhenDnEmbeddedInCnThenExtractsPrincipalName() throws Exception {
        Object principal = this.extractor.extractPrincipal(X509TestUtils.buildTestCertficateWithEmbeddedDn());

        assertEquals("luke", principal);
    }

    // gh-19254
    @Test
    public void extractWhenMultipleCnsThenExtractsMostSpecificCn() throws Exception {
        Object principal = this.extractor.extractPrincipal(X509TestUtils.buildTestCertificateWithMultipleCns());

        assertEquals("alice", principal);
    }

    @Test
    public void extractWhenEmailDnEmbeddedInCnThenExtractsEmail() throws Exception {
        this.extractor.setExtractPrincipalNameFromEmail(true);

        Object principal = this.extractor.extractPrincipal(X509TestUtils.buildTestCertficateWithEmbeddedEmailDn());

        assertEquals("luke@monkeymachine", principal);
    }

    @Test(expected = IllegalArgumentException.class)
    public void setMessageSourceWhenNullThenThrowsException() {
        this.extractor.setMessageSource(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void extractWhenCertificateIsNullThenFails() {
        this.extractor.extractPrincipal(null);
    }

}
