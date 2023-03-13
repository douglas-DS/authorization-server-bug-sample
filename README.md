## How to reproduce

- Request a new accessToken with the example request bellow:

```
curl --request POST \
--url 'http://localhost:8080/oauth2/token?grant_type=client_credentials&=' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA=='
```

- Make the same request again. At this point, the inconsistency between the store token's expiration 
and the `expires_in` property in the response body is evident. Even though the token is the 
same, the `expires_in` property doesn't change.