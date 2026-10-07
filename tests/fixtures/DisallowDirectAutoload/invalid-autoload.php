<?php

define('PUBLISHPRESS_FUTURE_LIB_VENDOR_PATH', '/path/to/lib/vendor');

require_once PUBLISHPRESS_FUTURE_LIB_VENDOR_PATH . '/publishpress/psr-container/lib/autoload.php';
require_once PUBLISHPRESS_FUTURE_LIB_VENDOR_PATH . '/publishpress/pimple-pimple/lib/autoload.php';
include PUBLISHPRESS_FUTURE_LIB_VENDOR_PATH . '/publishpress/foo-bar/lib/autoload.php';
require PUBLISHPRESS_FUTURE_LIB_VENDOR_PATH . "/publishpress/baz-qux/lib/autoload.php";
