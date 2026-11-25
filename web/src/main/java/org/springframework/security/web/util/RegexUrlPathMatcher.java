package org.springframework.security.web.util;

import java.util.regex.Pattern;

/**
 * @author Luke Taylor
 */
public class RegexUrlPathMatcher implements UrlMatcher {
    /**
     * The flags used to compile every URL pattern. {@link Pattern#DOTALL} is required so that
     * a wildcard such as "." also matches the line terminators which may be present in a
     * (decoded) request path. Without it, a request containing a carriage return or line feed
     * would fail to match a secured pattern and could bypass authorization.
     */
    private static final int DEFAULT = Pattern.DOTALL;

    private boolean requiresLowerCaseUrl = false;

    public Object compile(String path) {
        return Pattern.compile(path, DEFAULT);
    }

    public void setRequiresLowerCaseUrl(boolean requiresLowerCaseUrl) {
        this.requiresLowerCaseUrl = requiresLowerCaseUrl;
    }

    public boolean pathMatchesUrl(Object compiledPath, String url) {
        Pattern pattern = (Pattern)compiledPath;

        return pattern.matcher(url).matches();
    }

    public String getUniversalMatchPattern() {
        return "/.*";
    }

    public boolean requiresLowerCaseUrl() {
        return requiresLowerCaseUrl;
    }
}
