<?php

declare(strict_types=1);

namespace FireflyIII\Support\Minidauth;

/**
 * minidauth field sealing client for Firefly III.
 *
 * Talks to the language-agnostic minidauth-seal sidecar, which fronts minidauth and the Tide ORK
 * cohort. Sealing turns a plaintext value into "ms1:<ciphertext>"; opening reverses it, but only for a
 * reader the sidecar can verify AND whom minidauth's quorum grant says holds the reading role. This app
 * and its database only ever hold ciphertext; the vendor key lives as threshold shares across the
 * cohort and is never assembled here.
 *
 * Off unless MINIDAUTH_SEAL_URL is set. The reader token is a short-lived EdDSA (Ed25519) JWT signed
 * with a key only this app holds (MINIDAUTH_SEAL_SIGNING_KEY_FILE); minidauth verifies it with the
 * public half. PHP's openssl cannot sign Ed25519, so this uses libsodium: the 32-byte seed is the last
 * 32 bytes of the PKCS8 DER.
 */
class Sidecar
{
    public const string MARKER = 'ms1:';

    /**
     * Read an environment variable from every source. Laravel's dotenv is immutable, so .env values
     * reach $_ENV/$_SERVER but not getenv(); a docker/process var reaches getenv(). Check all three.
     */
    private static function env(string $key): string
    {
        $v = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);

        return false === $v || null === $v ? '' : (string) $v;
    }

    public static function enabled(): bool
    {
        return '' !== self::env('MINIDAUTH_SEAL_URL');
    }

    public static function isSealed(mixed $v): bool
    {
        return is_string($v) && str_starts_with($v, self::MARKER);
    }

    private static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function secretKey(): ?string
    {
        static $sk = false;
        if (false === $sk) {
            $file = self::env('MINIDAUTH_SEAL_SIGNING_KEY_FILE');
            $pem  = $file ? @file_get_contents($file) : self::env('MINIDAUTH_SEAL_SIGNING_KEY');
            if (!$pem) {
                return $sk = null;
            }
            // PKCS8 Ed25519: the 32-byte seed is the final 32 bytes of the DER.
            $der  = base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $pem));
            $seed = substr($der, -32);
            $sk   = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
        }

        return $sk;
    }

    /**
     * Mint a short-lived assertion that this already-authenticated user is the reader. The app has
     * verified the user; this token just carries that identity to the sidecar, which re-verifies the
     * signature and decrypts as this uid, gated by the quorum grant.
     */
    public static function readerToken(string $uid): string
    {
        $now     = time();
        $header  = self::b64url((string) json_encode(['alg' => 'EdDSA', 'typ' => 'JWT']));
        $payload = self::b64url((string) json_encode(['sub' => $uid, 'iat' => $now, 'exp' => $now + 15]));
        $sk      = self::secretKey();
        if (null === $sk) {
            throw new \RuntimeException('Set MINIDAUTH_SEAL_SIGNING_KEY_FILE');
        }
        $sig = self::b64url(sodium_crypto_sign_detached("{$header}.{$payload}", $sk));

        return "{$header}.{$payload}.{$sig}";
    }

    /**
     * Seal a 0-indexed list of plaintext strings, returning the ms1: values in order. Fails closed: a
     * sidecar error throws so a write never silently stores plaintext.
     *
     * @param string[] $values
     *
     * @return string[]
     */
    public static function seal(array $values): array
    {
        if (0 === count($values)) {
            return $values;
        }
        $fields = [];
        foreach ($values as $i => $v) {
            $fields[(string) $i] = $v;
        }
        $out    = self::post('/seal', ['fields' => $fields]);
        $result = [];
        foreach ($values as $i => $v) {
            $result[$i] = $out['sealed'][(string) $i];
        }

        return $result;
    }

    /**
     * Open a 0-indexed list of ms1: values as the reader named by $token. Best effort: any failure (no
     * reader, ungranted, sidecar down) returns the values unchanged (still sealed), so a read never
     * crashes and ciphertext is the safe default.
     *
     * @param string[] $values
     *
     * @return string[]
     */
    public static function open(array $values, ?string $token): array
    {
        if (0 === count($values) || null === $token) {
            return $values;
        }
        try {
            $fields = [];
            foreach ($values as $i => $v) {
                $fields[(string) $i] = substr($v, strlen(self::MARKER));
            }
            $out    = self::post('/open', ['fields' => $fields], $token);
            $result = [];
            foreach ($values as $i => $v) {
                $result[$i] = $out['fields'][(string) $i];
            }

            return $result;
        } catch (\Throwable) {
            return $values;
        }
    }

    private static function post(string $path, array $body, ?string $bearer = null): array
    {
        $url     = rtrim((string) self::env('MINIDAUTH_SEAL_URL'), '/') . $path;
        $headers = ['Content-Type: application/json'];
        if (null !== $bearer) {
            $headers[] = "Authorization: Bearer {$bearer}";
        }
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => (string) json_encode($body),
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 15,
        ]);
        $res  = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err  = curl_error($ch);
        curl_close($ch);
        if (false === $res) {
            throw new \RuntimeException("minidauth-seal {$path}: {$err}");
        }
        if ($code < 200 || $code >= 300) {
            throw new \RuntimeException("minidauth-seal {$path} -> {$code} {$res}");
        }

        return '' === (string) $res ? [] : (array) json_decode((string) $res, true);
    }
}
