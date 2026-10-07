<?php

namespace PublishPressStandards\Sniffs\Security;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;

class RequireDirectAccessGuardSniff implements Sniff
{
    /**
     * Canonical guard inserted by the fixer.
     *
     * @var string
     */
    private $guardLine = "if (!defined('ABSPATH')) exit; // Exit if accessed directly";

    /**
     * @var string
     */
    private $htmlFirstGuard = "<?php if (!defined('ABSPATH')) exit; // Exit if accessed directly\n?>";

    /**
     * @var string
     */
    private $processedFile = '';

    /**
     * @return int[]
     */
    public function register()
    {
        return [
            T_OPEN_TAG,
            T_INLINE_HTML,
        ];
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

        if ($this->processedFile === $filePath) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        if ($stackPtr !== 0) {
            return;
        }

        $this->processedFile = $filePath;

        if ($this->isUnderExcludedPath($filePath)) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        if ($this->fileStartsWithShebang($filePath)) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        $tokens = $phpcsFile->getTokens();
        $analysis = $this->analyzeFile($tokens);

        if ($analysis === null) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        if ($analysis['valid_guard_at_expected']) {
            return (count($phpcsFile->getTokens()) + 1);
        }

        if ($analysis['valid_guard_ptr'] !== null && !$analysis['valid_guard_at_expected']) {
            $phpcsFile->addError(
                'Direct-access guard must appear immediately after namespace and use statements, before any other code.',
                $analysis['valid_guard_ptr'],
                'WrongPosition'
            );

            return (count($phpcsFile->getTokens()) + 1);
        }

        $errorPtr = $analysis['expected_guard_ptr'];

        if ($errorPtr === false || !isset($tokens[$errorPtr])) {
            $errorPtr = $stackPtr;
        }

        if ($analysis['fixable']) {
            $fix = $phpcsFile->addFixableError(
                'PHP file is missing a direct-access guard (if (!defined(\'ABSPATH\')) exit;).',
                $errorPtr,
                'Missing'
            );

            if ($fix === true) {
                if ($analysis['html_first']) {
                    $phpcsFile->fixer->addContentBefore($stackPtr, $this->htmlFirstGuard);
                } else {
                    $phpcsFile->fixer->addContentBefore(
                        $analysis['insert_before_ptr'],
                        $this->guardLine . $phpcsFile->eolChar
                    );
                }
            }
        } else {
            $phpcsFile->addError(
                'PHP file is missing a direct-access guard (if (!defined(\'ABSPATH\')) exit;).',
                $errorPtr,
                'Missing'
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
     * @param string $filePath
     *
     * @return bool
     */
    private function fileStartsWithShebang($filePath)
    {
        $handle = fopen($filePath, 'rb');

        if ($handle === false) {
            return false;
        }

        $firstLine = fgets($handle);
        fclose($handle);

        if ($firstLine === false) {
            return false;
        }

        return (strpos($firstLine, '#!') === 0);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     *
     * @return array<string, mixed>|null
     */
    private function analyzeFile(array $tokens)
    {
        $count = count($tokens);

        if ($count === 0) {
            return null;
        }

        $htmlFirst = ($tokens[0]['code'] === T_INLINE_HTML);
        $ptr = 0;

        if ($htmlFirst) {
            $validGuardPtr = $this->findValidGuardInFile($tokens);

            return [
                'html_first' => true,
                'expected_guard_ptr' => 0,
                'insert_before_ptr' => 0,
                'valid_guard_ptr' => $validGuardPtr,
                'valid_guard_at_expected' => false,
                'fixable' => ($validGuardPtr === null),
            ];
        }

        $ptr = $this->findFirstOpenTag($tokens, $ptr);

        if ($ptr === false) {
            return null;
        }

        $ptr++;

        $ptr = $this->skipIgnorable($tokens, $ptr);

        while ($ptr < $count) {
            $ptr = $this->skipIgnorable($tokens, $ptr);

            if ($ptr >= $count) {
                break;
            }

            if ($tokens[$ptr]['code'] === T_DECLARE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($tokens[$ptr]['code'] === T_NAMESPACE) {
                $ptr = $this->skipNamespaceStatement($tokens, $ptr);
                continue;
            }

            break;
        }

        $preambleStart = $ptr;
        $lastUseEnd = $ptr;
        $stopCodes = [
            T_CLASS,
            T_INTERFACE,
            T_TRAIT,
            T_FUNCTION,
        ];

        while ($ptr < $count) {
            $ptr = $this->skipIgnorable($tokens, $ptr);

            if ($ptr >= $count) {
                break;
            }

            if (in_array($tokens[$ptr]['code'], $stopCodes, true)) {
                break;
            }

            if ($tokens[$ptr]['code'] === T_USE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                $lastUseEnd = $ptr;
                continue;
            }

            if ($tokens[$ptr]['code'] === T_IF) {
                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            break;
        }

        $expectedPtr = $this->skipIgnorable($tokens, $lastUseEnd);
        $insertBefore = $expectedPtr;

        if ($expectedPtr >= $count) {
            $insertBefore = max(0, $count - 1);
        }

        $guardAfterUses = $this->findGuardAfterUses($tokens, $lastUseEnd);
        $validGuardPtr = $this->findValidGuardInFile($tokens);
        $validAtExpected = ($guardAfterUses !== null
            && !$this->hasUseAfterGuard($tokens, $guardAfterUses));

        $fixable = ($validGuardPtr === null
            && !$this->hasNonPreambleBetween($tokens, $preambleStart, $lastUseEnd));

        return [
            'html_first' => false,
            'expected_guard_ptr' => $expectedPtr,
            'insert_before_ptr' => $insertBefore,
            'valid_guard_ptr' => $validGuardPtr,
            'valid_guard_at_expected' => $validAtExpected,
            'fixable' => $fixable,
        ];
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $start
     *
     * @return int|false
     */
    private function findFirstOpenTag(array $tokens, $start)
    {
        $count = count($tokens);

        for ($i = $start; $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_OPEN_TAG) {
                return $i;
            }
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int|null
     */
    private function findValidGuardInFile(array $tokens)
    {
        $count = count($tokens);

        for ($i = 0; $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_IF && $this->isDirectAccessGuardAt($tokens, $i)) {
                return $i;
            }
        }

        return null;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $lastUseEnd
     *
     * @return int|null
     */
    private function findGuardAfterUses(array $tokens, $lastUseEnd)
    {
        $ptr = $this->skipIgnorable($tokens, $lastUseEnd);

        if ($ptr >= count($tokens)) {
            return null;
        }

        if ($this->isDirectAccessGuardAt($tokens, $ptr)) {
            return $ptr;
        }

        return null;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $guardPtr
     *
     * @return bool
     */
    private function hasUseAfterGuard(array $tokens, $guardPtr)
    {
        $count = count($tokens);
        $stopCodes = [
            T_CLASS,
            T_INTERFACE,
            T_TRAIT,
            T_FUNCTION,
        ];

        for ($i = ($guardPtr + 1); $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_USE) {
                return true;
            }

            if (in_array($tokens[$i]['code'], $stopCodes, true)) {
                break;
            }
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $start
     * @param int                              $end
     *
     * @return bool
     */
    private function hasNonPreambleBetween(array $tokens, $start, $end)
    {
        $ptr = $start;
        $end = min($end, count($tokens));

        while ($ptr < $end) {
            $ptr = $this->skipIgnorable($tokens, $ptr);

            if ($ptr >= $end) {
                break;
            }

            if ($tokens[$ptr]['code'] === T_USE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            return true;
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int
     */
    private function skipIgnorable(array $tokens, $ptr)
    {
        $count = count($tokens);

        while ($ptr < $count && isset(Tokens::$emptyTokens[$tokens[$ptr]['code']])) {
            $ptr++;
        }

        return $ptr;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int
     */
    private function skipStatement(array $tokens, $ptr)
    {
        $count = count($tokens);
        $depth = 0;
        $started = false;

        for ($i = $ptr; $i < $count; $i++) {
            $code = $tokens[$i]['code'];

            if ($code === T_OPEN_CURLY_BRACKET) {
                $depth++;
                $started = true;
            } elseif ($code === T_CLOSE_CURLY_BRACKET) {
                $depth--;

                if ($depth === 0 && $started) {
                    return $i + 1;
                }
            } elseif ($code === T_SEMICOLON && $depth === 0) {
                return $i + 1;
            }
        }

        return $count;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int
     */
    private function skipNamespaceStatement(array $tokens, $ptr)
    {
        $count = count($tokens);
        $bracePtr = false;

        for ($i = $ptr; $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_OPEN_CURLY_BRACKET) {
                $bracePtr = $i;
                break;
            }

            if ($tokens[$i]['code'] === T_SEMICOLON) {
                return $i + 1;
            }
        }

        if ($bracePtr === false) {
            return $this->skipStatement($tokens, $ptr);
        }

        return $bracePtr + 1;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isDirectAccessGuardAt(array $tokens, $ptr)
    {
        $ptr = $this->skipIgnorable($tokens, $ptr);

        if (!isset($tokens[$ptr]) || $tokens[$ptr]['code'] !== T_IF) {
            return false;
        }

        $openParen = $this->skipIgnorable($tokens, $ptr + 1);

        if (!isset($tokens[$openParen]) || $tokens[$openParen]['code'] !== T_OPEN_PARENTHESIS) {
            return false;
        }

        $conditionEnd = $this->findMatchingParenthesisEnd($tokens, $openParen);

        if ($conditionEnd === false) {
            return false;
        }

        if (!$this->isAbspathUndefinedCondition($tokens, $openParen, $conditionEnd)) {
            return false;
        }

        $bodyPtr = $this->skipIgnorable($tokens, $conditionEnd + 1);

        if (!isset($tokens[$bodyPtr])) {
            return false;
        }

        if ($tokens[$bodyPtr]['code'] === T_EXIT
            && $this->isBareExitStatement($tokens, $bodyPtr)
        ) {
            return true;
        }

        if ($tokens[$bodyPtr]['code'] !== T_OPEN_CURLY_BRACKET) {
            return false;
        }

        $inner = $this->skipIgnorable($tokens, $bodyPtr + 1);

        if (!isset($tokens[$inner]) || $tokens[$inner]['code'] !== T_EXIT) {
            return false;
        }

        if (!$this->isBareExitStatement($tokens, $inner)) {
            return false;
        }

        $afterExit = $this->skipIgnorable($tokens, $inner + 2);

        return (isset($tokens[$afterExit])
            && $tokens[$afterExit]['code'] === T_CLOSE_CURLY_BRACKET);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $openParenPtr
     *
     * @return int|false
     */
    private function findMatchingParenthesisEnd(array $tokens, $openParenPtr)
    {
        if (!isset($tokens[$openParenPtr]) || $tokens[$openParenPtr]['code'] !== T_OPEN_PARENTHESIS) {
            return false;
        }

        $depth = 0;
        $count = count($tokens);

        for ($i = $openParenPtr; $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_OPEN_PARENTHESIS) {
                $depth++;
            } elseif ($tokens[$i]['code'] === T_CLOSE_PARENTHESIS) {
                $depth--;

                if ($depth === 0) {
                    return $i;
                }
            }
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $openParenPtr
     * @param int                              $closeParenPtr
     *
     * @return bool
     */
    private function isAbspathUndefinedCondition(array $tokens, $openParenPtr, $closeParenPtr)
    {
        $slice = '';

        for ($i = ($openParenPtr + 1); $i < $closeParenPtr; $i++) {
            $slice .= $tokens[$i]['content'];
        }

        $normalized = preg_replace('/\s+/', '', $slice);

        return (bool) preg_match(
            '/^!\\\\?defined\([\'"]ABSPATH[\'"]\)$/',
            $normalized
        );
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $exitPtr
     *
     * @return bool
     */
    private function isBareExitStatement(array $tokens, $exitPtr)
    {
        if (!isset($tokens[$exitPtr]) || $tokens[$exitPtr]['code'] !== T_EXIT) {
            return false;
        }

        $next = $exitPtr + 1;

        if (!isset($tokens[$next])) {
            return false;
        }

        if ($tokens[$next]['code'] === T_SEMICOLON) {
            return true;
        }

        if ($tokens[$next]['code'] === T_OPEN_PARENTHESIS) {
            return false;
        }

        return false;
    }
}
