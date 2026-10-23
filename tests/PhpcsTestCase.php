<?php

namespace PublishPressPhpcsStandards\Tests;

use PHPUnit\Framework\TestCase;

abstract class PhpcsTestCase extends TestCase
{
    /**
     * @param string   $fixtureRelativePath Path under tests/fixtures/.
     * @param string[] $sniffs              Fully qualified sniff codes.
     *
     * @return array<string, mixed>
     */
    protected function runPhpcsOnFixture($fixtureRelativePath, array $sniffs)
    {
        $fixture = $this->fixturePath($fixtureRelativePath);
        $phpcs   = $this->repositoryRoot() . '/vendor/bin/phpcs';

        $this->assertFileExists($phpcs, 'Run composer install before running tests.');
        $this->assertFileExists($fixture);

        $command = [
            $phpcs,
            '--standard=' . $this->repositoryRoot() . '/standards/PublishPressStandards',
            '--report=json',
            '-q',
        ];

        foreach ($sniffs as $sniff) {
            $command[] = '--sniffs=' . $sniff;
        }

        $command[] = $fixture;

        $process = proc_open(
            $command,
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $this->repositoryRoot()
        );

        $this->assertIsResource($process);

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        $this->assertSame('', $stderr, 'PHPCS stderr should be empty.');

        $report = json_decode($stdout, true);
        $this->assertIsArray($report, 'PHPCS did not return valid JSON: ' . $stdout);

        return $report;
    }

    /**
     * @param string   $fixtureRelativePath
     * @param string[] $sniffs
     *
     * @return string Absolute path to the fixed temporary copy.
     */
    protected function runPhpcbfOnFixtureCopy($fixtureRelativePath, array $sniffs)
    {
        $source = $this->fixturePath($fixtureRelativePath);
        $target = tempnam(sys_get_temp_dir(), 'pp-phpcs-') . '.php';
        copy($source, $target);

        $phpcbf = $this->repositoryRoot() . '/vendor/bin/phpcbf';
        $this->assertFileExists($phpcbf);

        $command = [
            $phpcbf,
            '--standard=' . $this->repositoryRoot() . '/standards/PublishPressStandards',
            '-q',
        ];

        foreach ($sniffs as $sniff) {
            $command[] = '--sniffs=' . $sniff;
        }

        $command[] = $target;

        $process = proc_open(
            $command,
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes,
            $this->repositoryRoot()
        );

        $this->assertIsResource($process);

        fclose($pipes[0]);
        stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        $this->assertSame('', $stderr, 'PHPCBF stderr should be empty.');

        return $target;
    }

    /**
     * @param array<string, mixed> $report
     * @param string               $fixturePath
     *
     * @return array<int, array<int, array<string, mixed>>>
     */
    protected function messagesForFixture(array $report, $fixturePath)
    {
        $files = $report['files'];
        $this->assertArrayHasKey($fixturePath, $files);

        return $files[$fixturePath]['messages'];
    }

    /**
     * @param string $relativePath
     *
     * @return string
     */
    protected function fixturePath($relativePath)
    {
        return $this->repositoryRoot() . '/tests/fixtures/' . $relativePath;
    }

    /**
     * @return string
     */
    protected function repositoryRoot()
    {
        return dirname(__DIR__);
    }
}
