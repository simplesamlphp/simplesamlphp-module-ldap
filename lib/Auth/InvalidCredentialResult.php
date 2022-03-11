<?php

namespace SimpleSAML\Module\ldap\Auth;

/**
 * Class representing an InvalidCredential Result
 *
 * This is used for extended diagnostic information
 *
 * @package SimpleSAML\Module\ldap\Auth
 */
class InvalidCredentialResult
{
    /**
     * List of Active Directory Bind Error Short Description's
     *
     * @see https://ldapwiki.com/wiki/Common%20Active%20Directory%20Bind%20Errors
     */
    const LDAP_NO_SUCH_OBJECT = '525';
    const ERROR_LOGON_FAILURE = '52e';
    const ERROR_ACCOUNT_RESTRICTION = '52f';
    const ERROR_INVALID_LOGON_HOURS = '530';
    const ERROR_INVALID_WORKSTATION = '531';
    const ERROR_PASSWORD_EXPIRED = '532';
    const ERROR_ACCOUNT_DISABLED = '533';
    const ERROR_TOO_MANY_CONTEXT_IDS = '568';
    const ERROR_ACCOUNT_EXPIRED = '701';
    const ERROR_PASSWORD_MUST_CHANGE = '773';
    const ERROR_ACCOUNT_LOCKED_OUT = '775';

    /**
     * List of Simple Bind error codes
     *
     * N.B. - This is an incomplete list
     */
    const NT_STATUS_PASSWORD_EXPIRED = 'PASSWORD_EXPIRED';
    const NT_STATUS_PASSWORD_MUST_CHANGE = 'PASSWORD_MUST_CHANGE';
    const NT_STATUS_LOGON_FAILURE = 'LOGON_FAILURE';

    /**
     * List of keys for the code mapping
     */
    const KEY_INVALID_CREDENTIAL = 'invalid_credential';
    const KEY_PASSWORD_ERROR = 'password_error';
    const KEY_ACCOUNT_ERROR = 'account_error';
    const KEY_RESTRICTION = 'restriction';

    /**
     * Map of keys to check the code against when using is* methods
     *
     * @var array
     */
    protected $codeMap = [
        self::KEY_INVALID_CREDENTIAL => [
            self::ERROR_LOGON_FAILURE,
            self::LDAP_NO_SUCH_OBJECT,
            self::NT_STATUS_LOGON_FAILURE,
        ],
        self::KEY_PASSWORD_ERROR     => [
            self::ERROR_PASSWORD_EXPIRED,
            self::ERROR_PASSWORD_MUST_CHANGE,
            self::NT_STATUS_PASSWORD_EXPIRED,
            self::NT_STATUS_PASSWORD_MUST_CHANGE
        ],
        self::KEY_ACCOUNT_ERROR      => [
            self::ERROR_ACCOUNT_DISABLED,
            self::ERROR_ACCOUNT_EXPIRED,
            self::ERROR_ACCOUNT_LOCKED_OUT
        ],
        self::KEY_RESTRICTION        => [
            self::ERROR_ACCOUNT_RESTRICTION,
            self::ERROR_INVALID_LOGON_HOURS,
            self::ERROR_INVALID_WORKSTATION,
            self::ERROR_TOO_MANY_CONTEXT_IDS
        ]
    ];

    /**
     * For Simple Binds this is the part after NT_STATUS_
     * Otherwise it is the HEX code from `data ([0-9a-f]+)`
     *
     * @var string The error code.
     */
    protected $code;

    /**
     * @var string the message as it came from LDAP
     */
    protected $rawMessage;

    /**
     * Parses the message when possible to determine what the actual error is
     *
     * @param string $message
     *
     * @return InvalidCredentialResult
     */
    public static function fromDiagnosticMessage(string $message): InvalidCredentialResult
    {
        if (strpos($message, 'Simple Bind Failed:') === 0) {
            list(, $tmp) = explode(':', $message, 2);
            $code = str_replace('NT_STATUS_', '', $tmp);
        } elseif (preg_match('/data\s(.*)?,/', $message, $match)) {
            $code = $match[1];
        }

        return new self($code, $message);
    }

    protected function __construct($code, $rawMessage)
    {
        $this->code       = $code;
        $this->rawMessage = $rawMessage;
    }

    /**
     * Returns the code that was pulled from the raw message
     *
     * @return string
     */
    public function getCode()
    {
        return $this->code;
    }

    /**
     * Returns the raw message
     *
     * @return string
     */
    public function getRawMessage()
    {
        return $this->rawMessage;
    }

    /**
     * Allows the default code mappings to be updated
     *
     * @param $codes
     */
    public function updateCodeMap($codes)
    {
        $this->codeMap = array_merge_recursive($this->codeMap, $codes);
    }

    /**
     * Allows the default code mappings to be replaced
     *
     * @param $codes
     */
    public function replaceCodeMap($codes)
    {
        $this->codeMap = $codes;
    }

    /**
     * @return bool Whether or not the password had an error
     */
    public function isPasswordError()
    {
        return in_array($this->code, $this->codeMap[self::KEY_PASSWORD_ERROR]);
    }

    /**
     * @return bool Whether or not the account had an error
     */
    public function isAccountError()
    {
        return in_array($this->code, $this->codeMap[self::KEY_ACCOUNT_ERROR]);
    }

    /**
     * @return bool Whether or not there was an auth problem
     */
    public function isInvalidCredential()
    {
        return in_array($this->code, $this->codeMap[self::KEY_INVALID_CREDENTIAL]);
    }

    /**
     * @return bool Whether or not there is a restriction in place
     */
    public function isRestricted()
    {
        return in_array($this->code, $this->codeMap[self::KEY_RESTRICTION]);
    }
}
