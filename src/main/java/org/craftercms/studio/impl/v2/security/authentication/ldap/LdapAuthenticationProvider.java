package org.craftercms.studio.impl.v2.security.authentication.ldap;

import jakarta.servlet.http.HttpServletRequest;
import org.craftercms.commons.http.RequestContext;
import org.craftercms.studio.api.v2.dal.User;
import org.craftercms.studio.api.v2.service.security.AccessTokenService;
import org.craftercms.studio.model.AuthenticatedUser;
import org.craftercms.studio.model.AuthenticationType;
import org.springframework.http.HttpHeaders;
import org.springframework.ldap.AuthenticationException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class LdapAuthenticationProvider implements AuthenticationProvider {

    private final LdapAuthService ldapAuthService; // Class riêng xử lý LDAP
    private final AccessTokenService accessTokenService;


    public LdapAuthenticationProvider(LdapAuthService ldapAuthService, AccessTokenService accessTokenService) {
        this.ldapAuthService = ldapAuthService;
        this.accessTokenService = accessTokenService;
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7); // Cắt bỏ "Bearer " để lấy token
        }
        return null;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return getAuthentication(authentication);
    }


    private Authentication getAuthentication(Authentication authentication) {
        HttpServletRequest request = RequestContext.getCurrent().getRequest();

        String token = getTokenFromRequest(request);
        if (token != null) {
//            username = accessTokenService.getUsername(token);
//            if(username == null) {
//                throw new BadCredentialsException("Invalid LDAP credentials");
//            }
            return SecurityContextHolder.getContext().getAuthentication();
        }

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        boolean isAuthenticated = ldapAuthService.authenticate(username, password);
        if (!isAuthenticated) {
            throw new BadCredentialsException("Invalid LDAP credentials");
        }

        User user = ldapAuthService.loadUserFromDB(username);
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(user);
        authenticatedUser.setAuthenticationType(AuthenticationType.LDAP);
        // Nếu thành công, trả về đối tượng Authentication
        Authentication authentication1 = new UsernamePasswordAuthenticationToken(authenticatedUser, null, null);
        SecurityContextHolder.getContext().setAuthentication(authentication1);
        return authentication1;
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
