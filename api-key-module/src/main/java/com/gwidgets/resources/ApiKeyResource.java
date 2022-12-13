package com.gwidgets.resources;

import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class ApiKeyResource {
    private static final String AUTH_METHOD = "X-API-KEY";
    private static final String INVALID_API_KEY = "INVALID_API_KEY";

    private KeycloakSession session;

    private final String realmName;

    public ApiKeyResource(KeycloakSession session) {
        this.session = session;
        String envRealmName = System.getenv("REALM_NAME");
        this.realmName = Objects.isNull(envRealmName) || Objects.equals(System.getenv(envRealmName), "") ? "example" : envRealmName;
    }

    @GET
    @Produces("application/json")
    public Response checkApiKey(@QueryParam("apiKey") String apiKey) {
        Response.Status status = Response.Status.UNAUTHORIZED;
        RealmModel realm = session.realms().getRealm(realmName);
        EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection());

        event.event(EventType.LOGIN);
        event.detail(Details.AUTH_METHOD, AUTH_METHOD);

        List<UserModel> matches = session.users()
                .searchForUserByUserAttributeStream(session.realms().getRealm(realmName), "api-key", apiKey)
                .filter(UserModel::isEnabled)
                .collect(Collectors.toList());

        if (matches.size() == 1) {
            status = Response.Status.OK;
            UserModel user = matches.get(0);
            event.user(user);
            event.success();
        } else {
            event.error(INVALID_API_KEY);
        }

        return Response.status(status).type(MediaType.APPLICATION_JSON).build();
    }
}
