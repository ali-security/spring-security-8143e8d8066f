package org.springframework.security.web.util;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * Tests for {@link RegexUrlPathMatcher}.
 */
public class RegexUrlPathMatcherTests {
    private final RegexUrlPathMatcher matcher = new RegexUrlPathMatcher();

    @Test
    public void matchesWithCarriageReturn() {
        Object compiled = matcher.compile(".*");

        assertTrue(matcher.pathMatchesUrl(compiled, "/blah\n"));
    }

    @Test
    public void matchesWithLineFeed() {
        Object compiled = matcher.compile(".*");

        assertTrue(matcher.pathMatchesUrl(compiled, "/blah\r"));
    }

    @Test
    public void securedPatternMatchesUrlContainingCarriageReturn() {
        Object compiled = matcher.compile("/secure/.*");

        assertTrue(matcher.pathMatchesUrl(compiled, "/secure/blah\n"));
    }

    @Test
    public void securedPatternMatchesUrlContainingLineFeed() {
        Object compiled = matcher.compile("/secure/.*");

        assertTrue(matcher.pathMatchesUrl(compiled, "/secure/blah\r"));
    }

    @Test
    public void universalMatchPatternMatchesUrlContainingLineTerminators() {
        Object compiled = matcher.compile(matcher.getUniversalMatchPattern());

        assertTrue(matcher.pathMatchesUrl(compiled, "/blah\r\n/more"));
    }

    @Test
    public void patternIsStillCaseSensitiveByDefault() {
        Object compiled = matcher.compile("/secure/.*");

        assertFalse(matcher.pathMatchesUrl(compiled, "/SECURE/blah"));
        assertFalse(matcher.requiresLowerCaseUrl());
    }

    @Test
    public void lowerCaseUrlConversionIsStillHonoured() {
        matcher.setRequiresLowerCaseUrl(true);

        assertTrue(matcher.requiresLowerCaseUrl());
        assertTrue(matcher.pathMatchesUrl(matcher.compile("/secure/.*"), "/SECURE/blah".toLowerCase()));
    }

    @Test
    public void nonMatchingUrlDoesntMatch() {
        Object compiled = matcher.compile("/secure/.*");

        assertFalse(matcher.pathMatchesUrl(compiled, "/insecure/blah"));
    }
}
