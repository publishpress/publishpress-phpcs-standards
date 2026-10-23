<?php

namespace PublishPressPhpcsStandards\Tests;

final class RequireGitAttributesSniffTest extends PhpcsTestCase
{
    /**
     * @var string
     */
    private $sniff = 'PublishPressStandards.Files.RequireGitAttributes';

    public function testFlagsMissingGitAttributesFile()
    {
        $fixture = $this->fixturePath('RequireGitAttributes/missing-gitattributes/publishpress-test.php');
        $report  = $this->runPhpcsOnFixture(
            'RequireGitAttributes/missing-gitattributes/publishpress-test.php',
            [$this->sniff]
        );

        $this->assertSame(1, $report['totals']['errors']);

        $messages = $this->messagesForFixture($report, $fixture);
        $this->assertSame($this->sniff . '.Missing', $messages[0]['source']);
    }

    public function testFlagsExistingPathNotMarkedExportIgnore()
    {
        $fixture = $this->fixturePath('RequireGitAttributes/missing-export-ignore/publishpress-test.php');
        $report  = $this->runPhpcsOnFixture(
            'RequireGitAttributes/missing-export-ignore/publishpress-test.php',
            [$this->sniff]
        );

        $this->assertGreaterThanOrEqual(1, $report['totals']['errors']);

        $messages = $this->messagesForFixture($report, $fixture);
        $sources  = array_column($messages, 'source');

        $this->assertContains($this->sniff . '.MissingExportIgnore', $sources);

        $exportIgnoreMessages = array_filter(
            $messages,
            function (array $message) {
                return $message['source'] === $this->sniff . '.MissingExportIgnore';
            }
        );
        $patterns = array_map(
            function (array $message) {
                return $message['message'];
            },
            $exportIgnoreMessages
        );

        $this->assertTrue(
            (bool) preg_grep('/tests/', $patterns),
            'Expected an error for the tests directory.'
        );
    }

    public function testAllowsOmittingPatternsThatDoNotExistOnDisk()
    {
        $fixture = $this->fixturePath('RequireGitAttributes/valid/publishpress-test.php');
        $report  = $this->runPhpcsOnFixture(
            'RequireGitAttributes/valid/publishpress-test.php',
            [$this->sniff]
        );

        $this->assertSame(0, $report['totals']['errors']);

        if (isset($report['files'][$fixture])) {
            $this->assertSame([], $report['files'][$fixture]['messages']);
        }
    }

    public function testSkipsFilesWithoutPluginHeader()
    {
        $fixture = $this->fixturePath('RequireGitAttributes/no-plugin-header/helper.php');
        $report  = $this->runPhpcsOnFixture(
            'RequireGitAttributes/no-plugin-header/helper.php',
            [$this->sniff]
        );

        $this->assertSame(0, $report['totals']['errors']);

        if (isset($report['files'][$fixture])) {
            $this->assertSame([], $report['files'][$fixture]['messages']);
        }
    }

    public function testTreatsBarePatternLineAsMissingExportIgnore()
    {
        $fixture = $this->fixturePath('RequireGitAttributes/bare-readme-line/publishpress-test.php');
        $report  = $this->runPhpcsOnFixture(
            'RequireGitAttributes/bare-readme-line/publishpress-test.php',
            [$this->sniff]
        );

        $this->assertGreaterThanOrEqual(1, $report['totals']['errors']);

        $messages = $this->messagesForFixture($report, $fixture);
        $readmeErrors = array_filter(
            $messages,
            function (array $message) {
                return $message['source'] === $this->sniff . '.MissingExportIgnore'
                    && strpos($message['message'], 'README.md') !== false;
            }
        );

        $this->assertNotEmpty($readmeErrors);
    }
}
