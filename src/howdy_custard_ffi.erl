%% Cryptography for howdy_custard, with Erlang's crypto and public_key:
%% checking RS256 signatures against a JWK's modulus and exponent, and
%% sealing session cookies with AES-256-GCM.
-module(howdy_custard_ffi).
-export([verify_rs256/4, seal/2, open/2]).

%% Whether Signature is Data signed with the RSA key whose modulus and
%% exponent are the big-endian bytes N and E.
verify_rs256(N, E, Data, Signature) ->
    Key = {'RSAPublicKey', binary:decode_unsigned(N), binary:decode_unsigned(E)},
    try public_key:verify(Data, sha256, Signature, Key)
    catch _:_ -> false
    end.

%% <<Nonce:12/binary, Tag:16/binary, Ciphertext/binary>>
seal(Key, Plaintext) ->
    Nonce = crypto:strong_rand_bytes(12),
    {Ciphertext, Tag} =
        crypto:crypto_one_time_aead(aes_256_gcm, Key, Nonce, Plaintext, <<>>, 16, true),
    <<Nonce/binary, Tag/binary, Ciphertext/binary>>.

open(Key, <<Nonce:12/binary, Tag:16/binary, Ciphertext/binary>>) ->
    try crypto:crypto_one_time_aead(aes_256_gcm, Key, Nonce, Ciphertext, <<>>, Tag, false) of
        error -> {error, nil};
        Plaintext -> {ok, Plaintext}
    catch _:_ -> {error, nil}
    end;
open(_, _) ->
    {error, nil}.
