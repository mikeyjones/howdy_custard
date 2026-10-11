%% An RSA key for tests: what a JWKS publishes of it, and signing with it.
-module(howdy_custard_test_ffi).
-export([new_key/0, sign/2]).

%% {Key, Modulus bytes, Exponent bytes}
new_key() ->
    Key = public_key:generate_key({rsa, 2048, 65537}),
    {'RSAPrivateKey', _, N, E, _, _, _, _, _, _, _} = Key,
    {Key, binary:encode_unsigned(N), binary:encode_unsigned(E)}.

sign(Key, Data) ->
    public_key:sign(Data, sha256, Key).
