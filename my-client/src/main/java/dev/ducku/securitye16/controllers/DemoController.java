package dev.ducku.securitye16.controllers;


import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class DemoController {

    private final OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;  // proxy - use to talk to the outside object
    private final RestTemplate restTemplate;

    public DemoController(OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager, RestTemplate restTemplate) {
        this.oAuth2AuthorizedClientManager = oAuth2AuthorizedClientManager;
        this.restTemplate = restTemplate;
    }

    @GetMapping("/token")
    public String token() {
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest
                .withClientRegistrationId("1")
                .principal("client_2")
                .build();

        OAuth2AuthorizedClient client = oAuth2AuthorizedClientManager.authorize(request); // request to the AS

        return client.getAccessToken().getTokenValue(); // added on the Authorization header on the request "Bearer ..."
    }

    @GetMapping("/demo")
    public String demo() {
        OAuth2AuthorizeRequest request = OAuth2AuthorizeRequest
                .withClientRegistrationId("1") //match with ClientRegistration object
                .principal("client")
                .build();
        OAuth2AuthorizedClient client = oAuth2AuthorizedClientManager.authorize(request);

        String token = client.getAccessToken().getTokenValue();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);
        headers.add("type", "jwt");
        HttpEntity<String> entity = new HttpEntity<>(headers);

        return restTemplate.exchange("http://localhost:9090/demo", HttpMethod.GET, entity, String.class).getBody();
    }
}
