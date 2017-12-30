package com.tianzhu.identity.uaa.account;

import com.tianzhu.identity.uaa.util.UaaTokenUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import java.net.URISyntaxException;

import static org.springframework.http.HttpStatus.OK;

@Controller
public class OpenIdConnectEndpoints {

    @Value("${issuer.uri:http://localhost:8080/uaa}")
    private String issuer;

    @RequestMapping(value = {"/.well-known/openid-configuration", "/oauth/token/.well-known/openid-configuration"})
    public ResponseEntity<OpenIdConfiguration> getOpenIdConfiguration(HttpServletRequest request) throws URISyntaxException {
        OpenIdConfiguration conf = new OpenIdConfiguration(getServerContextPath(request), getTokenEndpoint());
        return new ResponseEntity<>(conf, OK);
    }

    private String getServerContextPath(HttpServletRequest request) {
        StringBuffer requestURL = request.getRequestURL();
        return requestURL.substring(0, requestURL.length() - request.getServletPath().length());
    }

    public String getTokenEndpoint() throws URISyntaxException {
        return UaaTokenUtils.constructTokenEndpointUrl(issuer);
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}
