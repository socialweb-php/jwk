<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use PHPUnit\Framework\Attributes\DataProvider;
use SocialWeb\Jwk\KeyOperation;
use SocialWeb\Jwk\KeyUse;

class KeyOperationTest extends TestCase
{
    /**
     * @return iterable<string, array{KeyOperation, string, KeyUse}>
     */
    public static function operationProvider(): iterable
    {
        yield 'sign' => [KeyOperation::Sign, 'sign', KeyUse::Signature];
        yield 'verify' => [KeyOperation::Verify, 'verify', KeyUse::Signature];
        yield 'encrypt' => [KeyOperation::Encrypt, 'encrypt', KeyUse::Encryption];
        yield 'decrypt' => [KeyOperation::Decrypt, 'decrypt', KeyUse::Encryption];
        yield 'wrapKey' => [KeyOperation::WrapKey, 'wrapKey', KeyUse::Encryption];
        yield 'unwrapKey' => [KeyOperation::UnwrapKey, 'unwrapKey', KeyUse::Encryption];
        yield 'deriveKey' => [KeyOperation::DeriveKey, 'deriveKey', KeyUse::Encryption];
        yield 'deriveBits' => [KeyOperation::DeriveBits, 'deriveBits', KeyUse::Encryption];
    }

    #[DataProvider('operationProvider')]
    public function testIsBackedByTheRegisteredValueAndKnowsItsUse(
        KeyOperation $operation,
        string $value,
        KeyUse $use,
    ): void {
        $this->assertSame($value, $operation->value);
        $this->assertSame($use, $operation->keyUse());
    }

    public function testMatchesTheValueCaseSensitively(): void
    {
        $this->assertNull(KeyOperation::tryFrom('Sign'));
        $this->assertNull(KeyOperation::tryFrom('wrapkey'));
    }
}
