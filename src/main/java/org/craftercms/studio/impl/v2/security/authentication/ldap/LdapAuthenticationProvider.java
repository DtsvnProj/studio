package org.craftercms.studio.impl.v2.security.authentication.ldap;

import jakarta.servlet.http.HttpServletRequest;
import org.craftercms.commons.http.RequestContext;
import org.craftercms.studio.api.v2.dal.User;
import org.craftercms.studio.api.v2.service.security.AccessTokenService;
import org.craftercms.studio.api.v2.service.security.UserService;
import org.craftercms.studio.model.AuthenticatedUser;
import org.craftercms.studio.model.AuthenticationType;
import org.craftercms.studio.model.rest.CreateUserRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.ldap.AuthenticationException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class LdapAuthenticationProvider implements AuthenticationProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(LdapAuthenticationProvider.class);

    private final LdapAuthService ldapAuthService; // Class riêng xử lý LDAP
    private final AccessTokenService accessTokenService;
    private final UserService userService;


    public LdapAuthenticationProvider(LdapAuthService ldapAuthService, AccessTokenService accessTokenService, UserService userService) {
        this.ldapAuthService = ldapAuthService;
        this.accessTokenService = accessTokenService;
        this.userService = userService;
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
        if(user == null) {
            CreateUserRequest createUserRequest = ldapAuthService.getUserInfoFromAdToCreateUser(username, password);
            this.createUserIfNotExists(createUserRequest);
            user = ldapAuthService.loadUserFromDB(username);
        }

        AuthenticatedUser authenticatedUser = new AuthenticatedUser(user);
        authenticatedUser.setAuthenticationType(AuthenticationType.LDAP);
        // Nếu thành công, trả về đối tượng Authentication
        Authentication authentication1 = new UsernamePasswordAuthenticationToken(authenticatedUser, null, null);
        SecurityContextHolder.getContext().setAuthentication(authentication1);
        return authentication1;
    }

    private void createUserIfNotExists(CreateUserRequest createUserRequest) {
        createUserRequest.setEnabled(true);
        try {
            LOGGER.info("Creating user {}", createUserRequest.toString());
            userService.createUserInternal(buildUser(createUserRequest));
        }catch (Exception e) {
            e.printStackTrace();
        }
    }

    private User buildUser(final CreateUserRequest userRequest) {
        User user = new User();
        user.setUsername(userRequest.getUsername());
        user.setPassword(userRequest.getPassword());
        user.setFirstName(userRequest.getFirstName());
        user.setLastName(userRequest.getLastName());
        user.setExternallyManaged(userRequest.isExternallyManaged());
        user.setEmail(userRequest.getEmail());
        user.setEnabled(userRequest.isEnabled());
        return user;
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
