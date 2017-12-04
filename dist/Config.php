<?php
namespace Coercive\Security\Session;

use DateTime;

/**
 * @see \Coercive\Security\Session\Session
 */
class Config {

	/** @var bool If the session will autostart or not */
	private $_bActivate = true;

	/** @var string Init session domain */
	private $_sSessionDomain = '';

	/** @var string Init cookie domain */
	private $_sCookieDomain = '';

	/** @var string Init cookie path */
	private $_sCookiePath = '';

	/** @var string Init session path */
	private $_sSessionPath = '';

	/** @var string Init session name */
	private $_sSessionName = '';

	/** @var DateTime Init session date */
	private $_oSessionDate = null;

	/** @var bool Connection State */
	private $_bConnectionState = false;

	/** @var string Connection DB Table */
	private $_sConnectionTable = 'CONNECTION';

	/** @var string IP Connection DB Table */
	private $_sIpConnectionTable = 'IP_CONNECTION';

	/** @var string User Session Path */
	private $_sUserSessionPath = 'user';

	/** @var string Redirect Session Path */
	private $_sRedirectSessionPath = 'redirect';

	/** @var int Session Max Life Time */
	private $_iSessionMaxLifeTime = 0;

	/** @var int Cookie Life Time */
	private $_iCookieLifeTime = 0;

	/** @var bool Cookie Secure */
	private $_bCookieSecure = false;

	/** @var bool Cookie Http Only */
	private $_bCookieHttpOnly = false;

	/**
	 * Config constructor.
	 */
	public function __construct() {
		$this->_oSessionDate = new DateTime;
	}

	/**
	 * AUTO START SESSION
	 *
	 * The session objet will init session if not already active
	 *
	 * @param bool $bState
	 * @return $this
	 */
	public function setAutoStartSession($bState) {
		$this->_bActivate = (bool) $bState;
		return $this;
	}

	/** @return bool */
	public function isAutoStartSession() {
		return $this->_bActivate;
	}

	/**
	 * SESSION DOMAIN
	 *
	 * Ini set session domain
	 *
	 * @param string $sDomain
	 * @return $this
	 */
	public function setSessionDomain($sDomain) {
		$this->_sSessionDomain = (string) $sDomain;
		return $this;
	}

	/** @return string */
	public function getSessionDomain() {
		return $this->_sSessionDomain;
	}

	/**
	 * COOKIE DOMAIN
	 *
	 * Ini set cookie domain
	 *
	 * @param string $sDomain
	 * @return $this
	 */
	public function setCookieDomain($sDomain) {
		$this->_sCookieDomain = (string) $sDomain;
		return $this;
	}

	/** @return string */
	public function getCookieDomain() {
		return $this->_sCookieDomain;
	}

	/**
	 * COOKIE DOMAIN
	 *
	 * Ini set cookie path
	 *
	 * @param string $sPath
	 * @return $this
	 */
	public function setCookiePath($sPath) {
		$this->_sCookiePath = (string) $sPath;
		return $this;
	}

	/** @return string */
	public function getCookiePath() {
		return $this->_sCookiePath;
	}

	/**
	 * SET COOKIE LIFE TIME
	 *
	 * Ini set cookie life time
	 *
	 * @param int $iSeconds
	 * @return $this
	 */
	public function setCookieLifeTime($iSeconds) {
		$this->_iCookieLifeTime = (int) $iSeconds;
		return $this;
	}

	/** @return int */
	public function getCookieLifeTime() {
		return $this->_iCookieLifeTime;
	}

	/**
	 * SET COOKIE SECURE
	 *
	 * Ini set cookie secure
	 *
	 * @param bool $bState
	 * @return $this
	 */
	public function setCookieSecure($bState) {
		$this->_bCookieSecure = (bool) $bState;
		return $this;
	}

	/** @return bool */
	public function getCookieSecure() {
		return $this->_bCookieSecure;
	}

	/**
	 * SET COOKIE HTTP ONLY
	 *
	 * Ini set cookie httponly
	 *
	 * @param bool $bState
	 * @return $this
	 */
	public function setCookieHttpOnly($bState) {
		$this->_bCookieHttpOnly = (bool) $bState;
		return $this;
	}

	/** @return bool */
	public function getCookieHttpOnly() {
		return $this->_bCookieHttpOnly;
	}

	/**
	 * SESSION PATH
	 *
	 * Ini set session save path
	 *
	 * @param string $sPath
	 * @return $this
	 */
	public function setSessionPath($sPath) {
		$this->_sSessionPath = (string) $sPath;
		return $this;
	}

	/** @return string */
	public function getSessionPath() {
		return $this->_sSessionPath;
	}

	/**
	 * SESSION NAME
	 *
	 * Ini set session name
	 *
	 * @param string $sName
	 * @return $this
	 */
	public function setSessionName($sName) {
		$this->_sSessionName = (string) $sName;
		return $this;
	}

	/** @return string */
	public function getSessionName() {
		return $this->_sSessionName;
	}

	/**
	 * SESSION DATE
	 *
	 * Ini set session date
	 *
	 * @param DateTime $oDate
	 * @return $this
	 */
	public function setSessionDate(DateTime $oDate) {
		$this->_oSessionDate = $oDate;
		return $this;
	}

	/** @return DateTime */
	public function getSessionDate() {
		return $this->_oSessionDate;
	}

	/**
	 * SET CONNECTION STATE
	 *
	 * @param bool $bState
	 * @return $this
	 */
	public function setConnection($bState) {
		$this->_bConnectionState = (bool) $bState;
		return $this;
	}

	/**
	 * ENABLE CONNECTION
	 *
	 * @return $this
	 */
	public function enableConnection() {
		$this->_bConnectionState = true;
		return $this;
	}

	/**
	 * DISABLE CONNECTION
	 *
	 * @return $this
	 */
	public function disableConnection() {
		$this->_bConnectionState = false;
		return $this;
	}

	/** @return bool */
	public function getConnectionState() {
		return $this->_bConnectionState;
	}

	/**
	 * SET CONNECTION TABLE
	 *
	 * @param string $sTableName
	 * @return $this
	 */
	public function setConnectionTable($sTableName) {
		$this->_sConnectionTable = (string) $sTableName;
		return $this;
	}

	/** @return string */
	public function getConnectionTable() {
		return $this->_sConnectionTable;
	}

	/**
	 * SET IP CONNECTION TABLE
	 *
	 * @param string $sTableName
	 * @return $this
	 */
	public function setIpConnectionTable($sTableName) {
		$this->_sIpConnectionTable = (string) $sTableName;
		return $this;
	}

	/** @return string */
	public function getIpConnectionTable() {
		return $this->_sIpConnectionTable;
	}

	/**
	 * SET USER SESSION PATH
	 *
	 * @param string $sPath
	 * @return $this
	 */
	public function setUserSessionPath($sPath) {
		$this->_sUserSessionPath = (string) $sPath;
		return $this;
	}

	/** @return string */
	public function getUserSessionPath() {
		return $this->_sUserSessionPath;
	}

	/**
	 * SET REDIRECT SESSION PATH
	 *
	 * @param string $sPath
	 * @return $this
	 */
	public function setRedirectSessionPath($sPath) {
		$this->_sRedirectSessionPath = (string) $sPath;
		return $this;
	}

	/** @return string */
	public function getRedirectSessionPath() {
		return $this->_sRedirectSessionPath;
	}

	/**
	 * SET SESSION MAX LIFE TIME
	 *
	 * @param int $iSeconds
	 * @return $this
	 */
	public function setSessionMaxLifeTime($iSeconds) {
		$this->_iSessionMaxLifeTime = (int) $iSeconds;
		return $this;
	}

	/** @return int */
	public function getSessionMaxLifeTime() {
		return $this->_iSessionMaxLifeTime;
	}

}
