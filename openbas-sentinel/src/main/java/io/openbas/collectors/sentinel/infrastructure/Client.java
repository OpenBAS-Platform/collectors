package io.openbas.collectors.sentinel.infrastructure;

import com.microsoft.aad.msal4j.*;
import io.openbas.collectors.sentinel.infrastructure.config.AuthenticationProperties;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Collections;
import java.util.concurrent.ExecutionException;

@AllArgsConstructor
@Service
public class Client {

  private static IConfidentialClientApplication app;
  private final AuthenticationProperties authenticationProperties;

  public IAuthenticationResult fetchToken() throws IOException, ExecutionException, InterruptedException {
    // Ensure the app object is not re-created on each request, as it holds a token cache
    // If you are getting tokens for many tenants (millions), see the msal-client-credential-secret-high-availability sample
    // which shows how to use an in-memory token cache with eviction based on a size limit
    GetOrCreateApp(this.authenticationProperties.getClientId(), this.authenticationProperties.getClientSecret(),
        this.authenticationProperties.getAuthority().getUrl());

    ClientCredentialParameters clientCredentialParam = ClientCredentialParameters.builder(
            Collections.singleton(this.authenticationProperties.getScope()))
        .build();

    // The first time this is called, the app will make an HTTP request to the token issuer, so this is slow. Latency can be >1s
    return app.acquireToken(clientCredentialParam).get();
  }

  private static void GetOrCreateApp(String clientId, String secret, String authority) throws MalformedURLException {
    if (app == null) {
      app = ConfidentialClientApplication.builder(
              clientId,
              ClientCredentialFactory.createFromSecret(secret))
          .authority(authority)
          .build();
    }
  }
}
