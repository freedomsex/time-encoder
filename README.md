# Time Encoder

Time(delay) encoder based on JWT.

I needed to set a stateless delay. Between requests. The delay time is stored in token. The token is signed (APP_SECRET by default) with a secret key.
