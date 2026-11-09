<?php

/**
 * Checks the RFC examples copied under resources/ against the SHA-256
 * checksums in resources/manifest.json.
 *
 * Usage: php bin/check-fixtures.php [resources-directory]
 *
 * For each set the manifest names, the script lists every file in the set's
 * directory, sorts the paths byte by byte, computes the SHA-256 of each file,
 * and computes the SHA-256 of the resulting lines: the value, two spaces, and
 * the path with "./" in front. That is the method that resources/README.md
 * describes, and it gives the same value as the shell command there.
 *
 * It exits with 0 when every set matches and 1 when any does not.
 *
 * ---
 *
 * This file is part of socialweb/jwk
 *
 * Copyright © socialweb/jwk Contributors
 *
 * socialweb/jwk is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * socialweb/jwk is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with socialweb/jwk. If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

declare(strict_types=1);

$fail = static function (string $message): never {
    fwrite(STDERR, $message . "\n");

    exit(1);
};

/**
 * Returns every file under a directory, as paths from it with "./" in front,
 * sorted byte by byte
 *
 * @return list<string>
 */
$filesUnder = static function (string $directory) use ($fail): array {
    $files = [];
    $pending = [''];

    while ($pending !== []) {
        $current = array_pop($pending);
        $entries = scandir($directory . $current);

        if ($entries === false) {
            $fail(sprintf('Cannot read the directory %s', $directory . $current));
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            if (is_dir($directory . $current . '/' . $entry)) {
                $pending[] = $current . '/' . $entry;
            } else {
                $files[] = '.' . $current . '/' . $entry;
            }
        }
    }

    sort($files, SORT_STRING);

    return $files;
};

$resourcesDirectory = rtrim($argv[1] ?? __DIR__ . '/../resources', '/');
$manifestFile = $resourcesDirectory . '/manifest.json';
$json = @file_get_contents($manifestFile);

if ($json === false) {
    $fail(sprintf('Cannot read %s', $manifestFile));
}

/** @var mixed $manifest */
$manifest = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

if (!is_array($manifest) || !isset($manifest['sets']) || !is_array($manifest['sets'])) {
    $fail(sprintf('%s: the "sets" member is missing or is not a list', $manifestFile));
}

if (!array_is_list($manifest['sets'])) {
    $fail(sprintf('%s: the "sets" member is not a list', $manifestFile));
}

if ($manifest['sets'] === []) {
    $fail(sprintf('%s: the "sets" list is empty, so there is nothing to check', $manifestFile));
}

$failed = false;

/** @var array{name: string, sha256: string} $set */
foreach ($manifest['sets'] as $set) {
    $base = $resourcesDirectory . '/' . $set['name'];

    if (!is_dir($base)) {
        $fail(sprintf('%s: there is no directory %s in %s', $set['name'], $set['name'], $resourcesDirectory));
    }

    $files = $filesUnder($base);
    $lines = '';

    foreach ($files as $file) {
        $lines .= hash_file('sha256', $base . substr($file, 1)) . '  ' . $file . "\n";
    }

    $checksum = hash('sha256', $lines);

    if ($checksum === $set['sha256']) {
        printf("%s: OK (%d files, %s)\n", $set['name'], count($files), $checksum);

        continue;
    }

    $failed = true;

    printf(
        "%s: the checksum does not match\n  expected %s\n  computed %s\n",
        $set['name'],
        $set['sha256'],
        $checksum,
    );
}

exit($failed ? 1 : 0);
