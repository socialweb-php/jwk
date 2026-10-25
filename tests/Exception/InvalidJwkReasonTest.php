<?php

declare(strict_types=1);

namespace SocialWeb\Test\Jwk\Exception;

use SocialWeb\Jwk\Exception\InvalidJwkReason;
use SocialWeb\Test\Jwk\TestCase;

use function array_map;

class InvalidJwkReasonTest extends TestCase
{
    public function testHasTheReasonsOfTheDesign(): void
    {
        $this->assertSame(
            [
                'MalformedJson',
                'NotAnObject',
                'MissingMember',
                'WrongType',
                'UnsupportedKeyType',
                'UnsupportedCurve',
                'InvalidBase64Url',
                'NonMinimalInteger',
                'InvalidValue',
                'PointNotOnCurve',
                'WrongLength',
                'InconsistentPrivateMembers',
                'KeyPairMismatch',
                'PrivateMembersPresent',
                'SymmetricKey',
                'DuplicateKeyOperation',
                'InconsistentUseAndKeyOperations',
                'AlgorithmDoesNotFitKey',
                'InvalidCertificate',
                'CertificateKeyMismatch',
                'CertificateThumbprintMismatch',
            ],
            array_map(static fn (InvalidJwkReason $reason): string => $reason->name, InvalidJwkReason::cases()),
        );
    }
}
