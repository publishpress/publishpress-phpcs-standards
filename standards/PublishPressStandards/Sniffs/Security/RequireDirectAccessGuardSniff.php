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
    private $htmlFirstGuard = "<?php if (!defined('ABSPATH')) exit; // Exit if accessed directly\n?>\n";

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

        if ($analysis['guard_splits_docblock']) {
            $fix = $phpcsFile->addFixableError(
                'Direct-access guard must appear before the class, interface, trait, or function docblock.',
                $analysis['split_guard_ptr'],
                'SplitsDocblock'
            );

            if ($fix === true) {
                $this->relocateGuardBeforeDocblock(
                    $phpcsFile,
                    $analysis['split_guard_ptr'],
                    $analysis['insert_before_ptr']
                );
            }

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

        if ($analysis['non_standard_guard_ptr'] !== null) {
            $phpcsFile->addWarning(
                'Direct-access guard uses non-standard syntax; use if (!defined(\'ABSPATH\')) exit; instead.',
                $analysis['non_standard_guard_ptr'],
                'NonStandardSyntax'
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
                        $this->guardLine . $phpcsFile->eolChar . $phpcsFile->eolChar
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
            $nonStandardGuardPtr = null;

            if ($tokens[0]['code'] === T_OPEN_TAG) {
                $firstPhpBlockEnd = $this->findFirstPhpBlockEnd($tokens, 0);
                $nonStandardGuardPtr = $this->findNonStandardGuardBetween(
                    $tokens,
                    1,
                    $firstPhpBlockEnd
                );
            }

            return [
                'html_first' => true,
                'expected_guard_ptr' => 0,
                'insert_before_ptr' => 0,
                'valid_guard_ptr' => null,
                'non_standard_guard_ptr' => $nonStandardGuardPtr,
                'valid_guard_at_expected' => false,
                'guard_splits_docblock' => false,
                'split_guard_ptr' => null,
                'fixable' => ($nonStandardGuardPtr === null),
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
        $nonStandardGuardPtr = null;
        $stopCodes = $this->scopeStopCodes();

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
                if ($nonStandardGuardPtr === null
                    && $this->isNonStandardIfAbspathGuardAt($tokens, $ptr)
                ) {
                    $nonStandardGuardPtr = $this->skipIgnorable($tokens, $ptr);
                }

                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($this->isLegacyDirectAccessGuardAt($tokens, $ptr)) {
                if ($nonStandardGuardPtr === null) {
                    $nonStandardGuardPtr = $this->skipIgnorable($tokens, $ptr);
                }

                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            break;
        }

        $insertBefore = $this->findGuardInsertPtr($tokens, $lastUseEnd);
        $guardAfterUses = $this->findGuardAtExpectedPosition($tokens, $lastUseEnd);
        $validGuardPtr = $this->findValidGuardInFile($tokens);
        $validAtExpected = ($guardAfterUses !== null
            && !$this->hasUseAfterGuard($tokens, $guardAfterUses));
        $splitGuardPtr = $this->findGuardSplittingDocblock($tokens, $insertBefore);

        $fixable = ($validGuardPtr === null
            && $nonStandardGuardPtr === null
            && !$this->hasNonPreambleBetween($tokens, $preambleStart, $lastUseEnd));

        return [
            'html_first' => false,
            'expected_guard_ptr' => $insertBefore,
            'insert_before_ptr' => $insertBefore,
            'valid_guard_ptr' => $validGuardPtr,
            'non_standard_guard_ptr' => $nonStandardGuardPtr,
            'valid_guard_at_expected' => $validAtExpected,
            'guard_splits_docblock' => ($splitGuardPtr !== null),
            'split_guard_ptr' => $splitGuardPtr,
            'fixable' => $fixable,
        ];
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $openTagPtr
     *
     * @return int
     */
    private function findFirstPhpBlockEnd(array $tokens, $openTagPtr)
    {
        $count = count($tokens);

        for ($i = ($openTagPtr + 1); $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_INLINE_HTML) {
                return $i;
            }
        }

        return $count;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $start
     * @param int                              $limit
     *
     * @return int|null
     */
    private function findNonStandardGuardBetween(array $tokens, $start, $limit)
    {
        $ptr = $start;
        $limit = min($limit, count($tokens));
        $stopCodes = $this->scopeStopCodes();

        while ($ptr < $limit) {
            $ptr = $this->skipIgnorable($tokens, $ptr);

            if ($ptr >= $limit) {
                break;
            }

            if (in_array($tokens[$ptr]['code'], $stopCodes, true)) {
                break;
            }

            if ($tokens[$ptr]['code'] === T_USE) {
                $ptr = $this->skipStatement($tokens, $ptr);
                continue;
            }

            if ($tokens[$ptr]['code'] === T_IF
                && $this->isNonStandardIfAbspathGuardAt($tokens, $ptr)
            ) {
                return $this->skipIgnorable($tokens, $ptr);
            }

            if ($this->isLegacyDirectAccessGuardAt($tokens, $ptr)) {
                return $this->skipIgnorable($tokens, $ptr);
            }

            if ($tokens[$ptr]['code'] === T_INLINE_HTML) {
                break;
            }

            break;
        }

        return null;
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
     * @return bool
     */
    private function isNonStandardIfAbspathGuardAt(array $tokens, $ptr)
    {
        if ($this->isDirectAccessGuardAt($tokens, $ptr)) {
            return false;
        }

        $startPtr = $this->skipIgnorable($tokens, $ptr);

        if (!isset($tokens[$startPtr]) || $tokens[$startPtr]['code'] !== T_IF) {
            return false;
        }

        $openParen = $this->skipIgnorable($tokens, $startPtr + 1);

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

        return $this->isDieOrExitInvocation($tokens, $bodyPtr);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isLegacyDirectAccessGuardAt(array $tokens, $ptr)
    {
        $ptr = $this->skipIgnorable($tokens, $ptr);

        if (!$this->tokenIsDefinedFunction($tokens, $ptr)) {
            return false;
        }

        $afterDefined = $this->skipDefinedAbspathCall($tokens, $ptr);

        if ($afterDefined === false) {
            return false;
        }

        $operatorPtr = $this->skipIgnorable($tokens, $afterDefined);

        if (!isset($tokens[$operatorPtr]) || !$this->tokenIsLogicalOr($tokens[$operatorPtr])) {
            return false;
        }

        $afterOperator = $this->skipIgnorable($tokens, $operatorPtr + 1);

        return $this->tokenIsDieOrExitCall($tokens, $afterOperator);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function tokenIsDefinedFunction(array $tokens, $ptr)
    {
        if (!isset($tokens[$ptr])) {
            return false;
        }

        if (!$this->isStatementLevelExpressionStart($tokens, $ptr)) {
            return false;
        }

        if ($tokens[$ptr]['code'] === T_STRING
            && strtolower($tokens[$ptr]['content']) === 'defined'
        ) {
            return true;
        }

        if ($tokens[$ptr]['code'] === T_NAME_FULLY_QUALIFIED
            && preg_match('/^\\\\?defined$/i', $tokens[$ptr]['content']) === 1
        ) {
            return true;
        }

        return false;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $definedPtr
     *
     * @return int|false
     */
    private function skipDefinedAbspathCall(array $tokens, $definedPtr)
    {
        $openParen = $this->skipIgnorable($tokens, $definedPtr + 1);

        if (!isset($tokens[$openParen]) || $tokens[$openParen]['code'] !== T_OPEN_PARENTHESIS) {
            return false;
        }

        $closeParen = $this->findMatchingParenthesisEnd($tokens, $openParen);

        if ($closeParen === false) {
            return false;
        }

        $argument = '';

        for ($i = ($openParen + 1); $i < $closeParen; $i++) {
            $argument .= $tokens[$i]['content'];
        }

        $normalized = preg_replace('/\s+/', '', $argument);

        if (!preg_match('/^[\'"]ABSPATH[\'"]$/', $normalized)) {
            return false;
        }

        return $closeParen + 1;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isStatementLevelExpressionStart(array $tokens, $ptr)
    {
        $previous = ($ptr - 1);

        while ($previous >= 0) {
            if (isset(Tokens::$emptyTokens[$tokens[$previous]['code']])) {
                $previous--;
                continue;
            }

            break;
        }

        if ($previous < 0) {
            return true;
        }

        return !in_array($tokens[$previous]['code'], [T_OBJECT_OPERATOR, T_DOUBLE_COLON], true);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isDieOrExitInvocation(array $tokens, $ptr)
    {
        if (!isset($tokens[$ptr])) {
            return false;
        }

        if ($tokens[$ptr]['code'] === T_EXIT) {
            return true;
        }

        if ($tokens[$ptr]['code'] === T_STRING
            && strtolower($tokens[$ptr]['content']) === 'die'
        ) {
            return true;
        }

        if ($tokens[$ptr]['code'] !== T_OPEN_CURLY_BRACKET) {
            return false;
        }

        $inner = $this->skipIgnorable($tokens, $ptr + 1);

        if (!isset($tokens[$inner])) {
            return false;
        }

        if ($tokens[$inner]['code'] === T_EXIT) {
            return true;
        }

        return ($tokens[$inner]['code'] === T_STRING
            && strtolower($tokens[$inner]['content']) === 'die');
    }

    /**
     * @param array<int, array<string, mixed>> $token
     *
     * @return bool
     */
    private function tokenIsLogicalOr(array $token)
    {
        return ($token['code'] === T_LOGICAL_OR || $token['code'] === T_BOOLEAN_OR);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function tokenIsDieOrExitCall(array $tokens, $ptr)
    {
        if (!isset($tokens[$ptr])) {
            return false;
        }

        if ($tokens[$ptr]['code'] === T_EXIT) {
            return true;
        }

        return ($tokens[$ptr]['code'] === T_STRING
            && strtolower($tokens[$ptr]['content']) === 'die');
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
     * Where a missing guard is inserted.
     *
     * The file header docblock stays above the guard. A docblock on the next
     * class, interface, trait, or function stays below it.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $lastUseEnd
     *
     * @return int
     */
    private function findGuardInsertPtr(array $tokens, $lastUseEnd)
    {
        $count = count($tokens);
        $ptr = $this->skipWhitespaceAndInlineComments($tokens, $lastUseEnd);

        while ($ptr < $count && $this->isDocblockOpen($tokens, $ptr)) {
            if ($this->isStructureDocblock($tokens, $ptr) && !$this->isFileHeaderDocblock($tokens, $ptr)) {
                return $ptr;
            }

            $ptr = $this->docblockEnd($tokens, $ptr);
            $ptr = $this->skipWhitespaceAndInlineComments($tokens, $ptr);
        }

        if ($ptr >= $count) {
            return max(0, $count - 1);
        }

        return $ptr;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $lastUseEnd
     *
     * @return int|null
     */
    private function findGuardAtExpectedPosition(array $tokens, $lastUseEnd)
    {
        $count = count($tokens);
        $ptr = $this->skipWhitespaceAndInlineComments($tokens, $lastUseEnd);

        while ($ptr < $count && $this->isDocblockOpen($tokens, $ptr)) {
            if ($this->isStructureDocblock($tokens, $ptr) && !$this->isFileHeaderDocblock($tokens, $ptr)) {
                return null;
            }

            $ptr = $this->docblockEnd($tokens, $ptr);
            $ptr = $this->skipWhitespaceAndInlineComments($tokens, $ptr);
        }

        if ($ptr < $count && $this->isDirectAccessGuardAt($tokens, $ptr)) {
            return $ptr;
        }

        return null;
    }

    /**
     * Guard sitting between a structure docblock and that structure.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $insertPtr
     *
     * @return int|null
     */
    private function findGuardSplittingDocblock(array $tokens, $insertPtr)
    {
        if (!$this->isDocblockOpen($tokens, $insertPtr)
            || !$this->isStructureDocblock($tokens, $insertPtr)
            || $this->isFileHeaderDocblock($tokens, $insertPtr)
        ) {
            return null;
        }

        $ptr = $this->docblockEnd($tokens, $insertPtr);
        $ptr = $this->skipWhitespaceAndInlineComments($tokens, $ptr);

        if (!$this->isDirectAccessGuardAt($tokens, $ptr)) {
            return null;
        }

        $afterGuard = $this->endOfGuardStatement($tokens, $ptr);
        $afterGuard = $this->skipWhitespaceAndInlineComments($tokens, $afterGuard);
        $afterGuard = $this->skipDeclarationModifiers($tokens, $afterGuard);

        if (!$this->isStructureKeyword($tokens, $afterGuard)) {
            return null;
        }

        return $ptr;
    }

    /**
     * @param \PHP_CodeSniffer\Files\File $phpcsFile
     * @param int                         $guardPtr
     * @param int                         $docblockPtr
     *
     * @return void
     */
    private function relocateGuardBeforeDocblock(File $phpcsFile, $guardPtr, $docblockPtr)
    {
        $tokens = $phpcsFile->getTokens();
        $end = $this->endOfGuardStatement($tokens, $guardPtr);
        $chunk = '';

        for ($i = $guardPtr; $i < $end; $i++) {
            $chunk .= $tokens[$i]['content'];
        }

        $after = $end;
        $collapseAfter = (isset($tokens[$after])
            && $tokens[$after]['code'] === T_WHITESPACE
            && preg_match('/\A(?:\r\n|\n|\r)+([ \t]*)\z/', $tokens[$after]['content'], $matches) === 1);
        $before = $guardPtr - 1;

        $phpcsFile->fixer->beginChangeset();

        for ($i = $guardPtr; $i < $end; $i++) {
            $phpcsFile->fixer->replaceToken($i, '');
        }

        if ($collapseAfter) {
            $phpcsFile->fixer->replaceToken($after, $phpcsFile->eolChar . $matches[1]);

            if ($before >= 0
                && isset($tokens[$before])
                && $tokens[$before]['code'] === T_WHITESPACE
            ) {
                $phpcsFile->fixer->replaceToken($before, '');
            }
        }

        $phpcsFile->fixer->addContentBefore(
            $docblockPtr,
            rtrim($chunk) . $phpcsFile->eolChar . $phpcsFile->eolChar
        );
        $phpcsFile->fixer->endChangeset();
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $guardPtr
     *
     * @return int
     */
    private function endOfGuardStatement(array $tokens, $guardPtr)
    {
        $end = $this->skipStatement($tokens, $guardPtr);
        $count = count($tokens);
        $guardLine = $tokens[$guardPtr]['line'];

        while ($end < $count && $tokens[$end]['code'] === T_WHITESPACE) {
            if (strpos($tokens[$end]['content'], "\n") !== false
                || strpos($tokens[$end]['content'], "\r") !== false
            ) {
                break;
            }

            $end++;
        }

        if ($end < $count
            && $tokens[$end]['code'] === T_COMMENT
            && $tokens[$end]['line'] === $guardLine
        ) {
            $end++;
        }

        return $end;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isDocblockOpen(array $tokens, $ptr)
    {
        return (isset($tokens[$ptr]) && $tokens[$ptr]['code'] === T_DOC_COMMENT_OPEN_TAG);
    }

    /**
     * First docblock in the file, before namespace or other code.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isFileHeaderDocblock(array $tokens, $ptr)
    {
        if (!$this->isDocblockOpen($tokens, $ptr)) {
            return false;
        }

        $count = count($tokens);
        $first = null;

        for ($i = 0; $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_DOC_COMMENT_OPEN_TAG) {
                $first = $i;
                break;
            }
        }

        if ($first !== $ptr) {
            return false;
        }

        for ($i = 0; $i < $ptr; $i++) {
            $code = $tokens[$i]['code'];

            if ($code === T_OPEN_TAG || $code === T_WHITESPACE || $code === T_COMMENT) {
                continue;
            }

            if ($code === T_DECLARE) {
                $i = $this->skipStatement($tokens, $i) - 1;
                continue;
            }

            return false;
        }

        return true;
    }

    /**
     * Docblock attached to the following class, interface, trait, or function.
     *
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isStructureDocblock(array $tokens, $ptr)
    {
        $after = $this->docblockEnd($tokens, $ptr);
        $after = $this->skipWhitespaceAndInlineComments($tokens, $after);

        if ($this->isDirectAccessGuardAt($tokens, $after)) {
            $after = $this->endOfGuardStatement($tokens, $after);
            $after = $this->skipWhitespaceAndInlineComments($tokens, $after);
        }

        $after = $this->skipDeclarationModifiers($tokens, $after);

        return $this->isStructureKeyword($tokens, $after);
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return int Index of the first token after the docblock.
     */
    private function docblockEnd(array $tokens, $ptr)
    {
        if (isset($tokens[$ptr]['comment_closer'])) {
            return $tokens[$ptr]['comment_closer'] + 1;
        }

        $count = count($tokens);

        for ($i = $ptr; $i < $count; $i++) {
            if ($tokens[$i]['code'] === T_DOC_COMMENT_CLOSE_TAG) {
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
    private function skipWhitespaceAndInlineComments(array $tokens, $ptr)
    {
        $count = count($tokens);

        while ($ptr < $count
            && ($tokens[$ptr]['code'] === T_WHITESPACE || $tokens[$ptr]['code'] === T_COMMENT)
        ) {
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
    private function skipDeclarationModifiers(array $tokens, $ptr)
    {
        $count = count($tokens);

        while ($ptr < $count) {
            $code = $tokens[$ptr]['code'];

            if ($code === T_ABSTRACT
                || $code === T_FINAL
                || (defined('T_READONLY') && $code === T_READONLY)
            ) {
                $ptr++;
                $ptr = $this->skipWhitespaceAndInlineComments($tokens, $ptr);
                continue;
            }

            if (defined('T_ATTRIBUTE') && $code === T_ATTRIBUTE) {
                if (!isset($tokens[$ptr]['attribute_closer'])) {
                    break;
                }

                $ptr = $tokens[$ptr]['attribute_closer'] + 1;
                $ptr = $this->skipWhitespaceAndInlineComments($tokens, $ptr);
                continue;
            }

            break;
        }

        return $ptr;
    }

    /**
     * @param array<int, array<string, mixed>> $tokens
     * @param int                              $ptr
     *
     * @return bool
     */
    private function isStructureKeyword(array $tokens, $ptr)
    {
        if (!isset($tokens[$ptr])) {
            return false;
        }

        $codes = $this->scopeStopCodes();

        if (defined('T_ENUM')) {
            $codes[] = T_ENUM;
        }

        return in_array($tokens[$ptr]['code'], $codes, true);
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
        $stopCodes = $this->scopeStopCodes();

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
     * Tokens that end the file preamble. A `use` inside a closure imports
     * variables, not a namespace.
     *
     * @return int[]
     */
    private function scopeStopCodes()
    {
        return [
            T_CLASS,
            T_INTERFACE,
            T_TRAIT,
            T_FUNCTION,
            T_CLOSURE,
            T_FN,
        ];
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
