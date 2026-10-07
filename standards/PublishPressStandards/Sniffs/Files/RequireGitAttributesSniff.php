<?php

namespace PublishPressStandards\Sniffs\Files;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

class RequireGitAttributesSniff implements Sniff
{
    /**
     * Paths commonly export-ignored across PublishPress plugin repositories.
     *
     * @var string[]
     */
    public $commonExportIgnorePatterns = [
        '.babelrc',
        '.distignore',
        '.env.example',
        '.gitattributes',
        '.git',
        '.github',
        '.gitignore',
        '.phpcs.xml',
        '.phplint.yml',
        '.rsync-filters-post-build',
        '.rsync-filters-pre-build',
        '.vscode',
        '.wordpress-org',
        '*.code-workspace',
        'bin',
        'builder.yml',
        'dev-workspace',
        'dist',
        'Gruntfile.js',
        'jsconfig.json',
        'node_modules',
        'package.json',
        'package-lock.json',
        'psalm.xml',
        'README.md',
        'RoboFile.php',
        'tests',
        'webpack.config.js',
    ];

    /**
     * @return int[]
     */
    public function register()
    {
        return [T_OPEN_TAG];
    }

    /**
     * @param \PHP_CodeSniffer\Files\File $phpcsFile
     * @param int                         $stackPtr
     *
     * @return void|int
     */
    public function process(File $phpcsFile, $stackPtr)
    {
        $filePath = $phpcsFile->getFilename();

        if ($this->isUnderExcludedPath($filePath)) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        if (!$this->isPluginMainFile($phpcsFile)) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        $pluginRoot = dirname($filePath);
        $gitAttributesPath = $pluginRoot . DIRECTORY_SEPARATOR . '.gitattributes';

        if (!is_file($gitAttributesPath)) {
            $phpcsFile->addError(
                'Plugin root is missing a .gitattributes file for export-ignore rules.',
                $stackPtr,
                'Missing'
            );

            return (count($phpcsFile->getTokens()) + 1);
        }

        $exportIgnored = $this->parseExportIgnoredPatterns($gitAttributesPath);

        foreach ($this->commonExportIgnorePatterns as $pattern) {
            if (!$this->patternExistsAtPluginRoot($pluginRoot, $pattern)) {
                continue;
            }

            if ($this->isPatternExportIgnored($pattern, $exportIgnored)) {
                continue;
            }

            $phpcsFile->addError(
                'Path "%s" exists in the plugin root but is not marked export-ignore in .gitattributes.',
                $stackPtr,
                'MissingExportIgnore',
                [$pattern]
            );
        }

        return (count($phpcsFile->getTokens()) + 1);
    }

    /**
     * @param string $filePath
     *
     * @return bool
     */
    private function isUnderExcludedPath($filePath)
    {
        $normalized = str_replace('\\', '/', $filePath);

        return (strpos($normalized, '/vendor/') !== false
            || strpos($normalized, '/node_modules/') !== false);
    }

    /**
     * @param \PHP_CodeSniffer\Files\File $phpcsFile
     *
     * @return bool
     */
    private function isPluginMainFile(File $phpcsFile)
    {
        $header = $phpcsFile->getTokensAsString(0, min(50, count($phpcsFile->getTokens())));

        return (strpos($header, 'Plugin Name:') !== false);
    }

    /**
     * @param string $gitAttributesPath
     *
     * @return string[]
     */
    private function parseExportIgnoredPatterns($gitAttributesPath)
    {
        $patterns = [];
        $lines = file($gitAttributesPath, FILE_IGNORE_NEW_LINES);

        if ($lines === false) {
            return $patterns;
        }

        foreach ($lines as $line) {
            $line = trim($line);

            if ($line === '' || strpos($line, '#') === 0) {
                continue;
            }

            $parts = preg_split('/\s+/', $line);

            if (!is_array($parts) || count($parts) < 2) {
                continue;
            }

            $pattern = $this->normalizePattern($parts[0]);
            $attributes = array_slice($parts, 1);

            if (in_array('export-ignore', $attributes, true)) {
                $patterns[] = $pattern;
            }
        }

        return $patterns;
    }

    /**
     * @param string $pattern
     *
     * @return string
     */
    private function normalizePattern($pattern)
    {
        $pattern = trim($pattern, '"\'');

        if (strpos($pattern, './') === 0) {
            $pattern = substr($pattern, 2);
        }

        $pattern = ltrim($pattern, '/');
        $pattern = rtrim($pattern, '/');

        return $pattern;
    }

    /**
     * @param string $pluginRoot
     * @param string $pattern
     *
     * @return bool
     */
    private function patternExistsAtPluginRoot($pluginRoot, $pattern)
    {
        if (strpos($pattern, '*') !== false || strpos($pattern, '?') !== false) {
            return $this->globMatchesAtPluginRoot($pluginRoot, $pattern);
        }

        $path = $pluginRoot . DIRECTORY_SEPARATOR . $pattern;

        return is_file($path) || is_dir($path);
    }

    /**
     * @param string $pluginRoot
     * @param string $globPattern
     *
     * @return bool
     */
    private function globMatchesAtPluginRoot($pluginRoot, $globPattern)
    {
        if (!is_dir($pluginRoot)) {
            return false;
        }

        $entries = scandir($pluginRoot);

        if ($entries === false) {
            return false;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            if (fnmatch($globPattern, $entry)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string   $pattern
     * @param string[] $exportIgnored
     *
     * @return bool
     */
    private function isPatternExportIgnored($pattern, array $exportIgnored)
    {
        $normalized = $this->normalizePattern($pattern);

        foreach ($exportIgnored as $ignored) {
            if ($ignored === $normalized) {
                return true;
            }
        }

        return false;
    }
}
