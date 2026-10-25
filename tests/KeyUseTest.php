<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk;

use SocialWeb\Jwk\KeyOperation;
use SocialWeb\Jwk\KeyUse;

class KeyUseTest extends TestCase
{
    public function testIsBackedByTheRegisteredUseValues(): void
    {
        $this->assertSame('sig', KeyUse::Signature->value);
        $this->assertSame('enc', KeyUse::Encryption->value);
        $this->assertNull(KeyUse::tryFrom('SIG'));
    }

    public function testASignatureKeySignsAndVerifies(): void
    {
        $this->assertSame([KeyOperation::Sign, KeyOperation::Verify], KeyUse::Signature->operations());
    }

    public function testAnEncryptionKeyEncryptsWrapsAndDerives(): void
    {
        $this->assertSame(
            [
                KeyOperation::Encrypt,
                KeyOperation::Decrypt,
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
                KeyOperation::DeriveKey,
                KeyOperation::DeriveBits,
            ],
            KeyUse::Encryption->operations(),
        );
    }
}
