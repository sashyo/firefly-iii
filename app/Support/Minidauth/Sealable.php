<?php

declare(strict_types=1);

namespace FireflyIII\Support\Minidauth;

/**
 * Seal selected Eloquent attributes with minidauth before they reach the database, and open them again
 * when a model is read, as the signed-in user (auth()->id()), gated by a quorum-granted role.
 *
 * A model uses the trait and declares which attributes it seals:
 *
 *   class Account extends Model {
 *       use Sealable;
 *       public array $minidauthSealed = ['name', 'iban'];
 *   }
 *
 * Off unless MINIDAUTH_SEAL_URL is set, in which case every path is a no-op and the model behaves
 * exactly like upstream.
 */
trait Sealable
{
    public static function bootSealable(): void
    {
        // seal on the way in
        static::saving(static function ($model): void {
            if (!Sidecar::enabled()) {
                return;
            }
            $plain = [];
            foreach ($model->minidauthSealed ?? [] as $field) {
                $value = $model->getAttribute($field);
                if (is_string($value) && '' !== $value && !Sidecar::isSealed($value)) {
                    $plain[$field] = $value;
                }
            }
            if (0 === count($plain)) {
                return;
            }
            $sealed = Sidecar::seal(array_values($plain)); // fails closed: a sidecar error throws here
            $i      = 0;
            foreach (array_keys($plain) as $field) {
                $model->setAttribute($field, $sealed[$i]);
                ++$i;
            }
        });

        // open on the way out, as the signed-in user
        static::retrieved(static function ($model): void {
            if (!Sidecar::enabled()) {
                return;
            }
            $sealedValues = [];
            foreach ($model->minidauthSealed ?? [] as $field) {
                $value = $model->getAttribute($field);
                if (Sidecar::isSealed($value)) {
                    $sealedValues[$field] = $value;
                }
            }
            if (0 === count($sealedValues)) {
                return;
            }
            $uid    = auth()->id();
            $token  = null !== $uid ? Sidecar::readerToken((string) $uid) : null;
            $opened = Sidecar::open(array_values($sealedValues), $token); // best effort; stays sealed on failure
            $i      = 0;
            foreach (array_keys($sealedValues) as $field) {
                $model->setAttribute($field, $opened[$i]);
                $model->syncOriginalAttribute($field); // the opened value is not a change to persist
                ++$i;
            }
        });
    }
}
