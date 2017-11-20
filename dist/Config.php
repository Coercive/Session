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

	/**
	 * Config constructor.
	 */
	public function __construct() {
		$this->_oSessionDate = new DateTime;
	}

########################################################################################################################
# SETTERS PART
########################################################################################################################

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

########################################################################################################################
# GETTERS PART
########################################################################################################################

	/**
	 * @return bool
	 */
	public function isAutoStartSession() {
		return $this->_bActivate;
	}

	/**
	 * @return string
	 */
	public function getSessionDomain() {
		return $this->_sSessionDomain;
	}

	/**
	 * @return string
	 */
	public function getCookieDomain() {
		return $this->_sCookieDomain;
	}

	/**
	 * @return string
	 */
	public function getSessionPath() {
		return $this->_sSessionPath;
	}

	/**
	 * @return string
	 */
	public function getSessionName() {
		return $this->_sSessionName;
	}

	/**
	 * @return DateTime
	 */
	public function getSessionDate() {
		return $this->_oSessionDate;
	}

	/**
	 * @return bool
	 */
	public function getConnectionState() {
		return $this->_bConnectionState;
	}

	/**
	 * @return string
	 */
	public function getConnectionTable() {
		return $this->_sConnectionTable;
	}

	/**
	 * @return string
	 */
	public function getIpConnectionTable() {
		return $this->_sIpConnectionTable;
	}

	/**
	 * @return string
	 */
	public function getUserSessionPath() {
		return $this->_sUserSessionPath;
	}

	/**
	 * @return string
	 */
	public function getRedirectSessionPath() {
		return $this->_sRedirectSessionPath;
	}

}