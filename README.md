## How to reproduce

- Request a new accessToken with the example request bellow:

```
curl --request POST \
--url 'http://localhost:8080/oauth2/token?grant_type=client_credentials&=' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='
```

- Do the same request again. At this point the inconsistency between the actual expiration 
of the token and the `expires_in` property in the response is evident.