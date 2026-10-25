<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk\Exception;

use RuntimeException;
use SocialWeb\Jwk\Exception\ConversionFailed;
use SocialWeb\Jwk\Exception\ConversionFailedReason;
use SocialWeb\Jwk\Exception\JwkException;
use SocialWeb\Test\Jwk\TestCase;

class ConversionFailedTest extends TestCase
{
    public function testCanBeCaughtAsAJwkException(): void
    {
        $this->expectException(JwkException::class);

        throw new ConversionFailed(ConversionFailedReason::SymmetricKey, 'A symmetric key has no public form');
    }

    public function testCanBeCaughtAsARuntimeException(): void
    {
        $this->expectException(RuntimeException::class);

        throw new ConversionFailed(ConversionFailedReason::SymmetricKey, 'A symmetric key has no public form');
    }

    public function testHasTheReasonTheMessageAndThePrevious(): void
    {
        $previous = new RuntimeException('cause');
        $exception = new ConversionFailed(ConversionFailedReason::UnreadablePem, 'OpenSSL could not read', $previous);

        $this->assertSame(ConversionFailedReason::UnreadablePem, $exception->reason);
        $this->assertSame('OpenSSL could not read', $exception->getMessage());
        $this->assertSame($previous, $exception->getPrevious());
        $this->assertSame(0, $exception->getCode());
    }
}
