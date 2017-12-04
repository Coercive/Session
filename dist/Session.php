<?php
namespace Coercive\Security\Session;

use DateTime;
use Exception;

/**
 * Session
 *
 * @package 	Coercive\Security\Session
 * @link		https://github.com/Coercive/Session
 *
 * @author  	Anthony Moral <contact@coercive.fr>
 * @copyright   2017 - 2018 Anthony Moral
 * @license 	http://www.gnu.org/copyleft/lesser.html GNU Lesser General Public License
 */
class Session {

	/** @var Config */
	private $_oConfig = null;

	/** @var DateTime */
	private $_oDate = null;

	/** @var Redirect */
	private $_oRedirect = null;

	/** @var User */
	private $_oUser = null;

	/**
	 * Vérifie la validité de l'ID de session
	 *
	 * @return bool
	 */
	private function _isValidId() {
		return preg_match('/^[-,a-zA-Z0-9]{1,128}$/', session_id()) > 0;
	}

	/**
	 * Session constructor.
	 *
	 * @param Config $oConfig [optional]
	 * @throws Exception
	 */
	public function __construct(Config $oConfig = null) {

		# Autoload Config with default values
		if(null === $oConfig) { $oConfig = new Config; }
		$this->_oConfig = $oConfig;

		# Ini set custom session domain
		if($sSessionDomain = $oConfig->getSessionDomain()) {
			$this->setSessionDomain($sSessionDomain);
		}

		# Ini set custom cookie domain
		if($sCookieDomain = $oConfig->getCookieDomain()) {
			$this->setCookieDomain($sCookieDomain);
		}

		# Ini set custom session path
		if($sSessionPath = $oConfig->getSessionDomain()) {
			$this->setSessionPath($sSessionPath);
		}

		# Ini set custom session name
		if($sSessionName = $oConfig->getSessionName()) {
			$this->setSessionName($sSessionName);
		}

		# Ini set session max life time
		if($iSessionMaxTime = $oConfig->getSessionName()) {
			$this->setSessionMaxLifeTime($iSessionMaxTime);
		}

		# Ini set cookie life time
		if($iCookieLifeTime = $oConfig->getCookieLifeTime()) {
			$this->setCookieLifeTime($iCookieLifeTime);
		}

		# Ini set cookie path
		if($sCookiePath = $oConfig->getCookiePath()) {
			$this->setCookiePath($sCookiePath);
		}

		# Ini set cookie secure
		if($bCookieSecure = $oConfig->getCookieSecure()) {
			$this->setCookieSecure($bCookieSecure);
		}

		# Ini set cookie httponly
		if($bCookieHttpOnly = $oConfig->getCookieHttpOnly()) {
			$this->setCookieHttpOnly($bCookieHttpOnly);
		}

		# Start session with verification
		if ($oConfig->isAutoStartSession()) {
			$this->startSession();
		}

		# TimeStamp
		$this->_oDate = $oConfig->getSessionDate();

		# Redirect
		$this->_oRedirect = new Redirect($this);

		# User
		$this->_oUser = new User($this);

	}

	/**
	 * GET CONFIG
	 *
	 * @return Config
	 */
	public function Config() {
		return $this->_oConfig;
	}

	/**
	 * GET REDIRECT
	 *
	 * @return Redirect
	 */
	public function Redirect() {
		return $this->_oRedirect;
	}

	/**
	 * GET USER
	 *
	 * @return Redirect
	 */
	public function User() {
		return $this->_oRedirect;
	}

	/**
	 * IS SESSION ACTIVE
	 *
	 * @return bool
	 */
	public function isActive() {
		return session_status() === PHP_SESSION_ACTIVE && session_id() !== '' && $this->_isValidId();
	}

	/**
	 * START SESSION
	 *
	 * @return $this
	 * @throws Exception
	 */
	public function startSession() {

		# Already
		if($this->isActive()) { return $this; }

		# Start
		if(!@session_start()) {
			session_destroy();
			if(!session_start()) {
				throw new Exception("Can't start session.");
			}
		}

		# Maintain chainability
		return $this;

	}

	/**
	 * SET SESSION DOMAIN
	 *
	 * @param string $sSessionDomain
	 * @return $this
	 */
	public function setSessionDomain($sSessionDomain) {
		ini_set('session.session_domain', "$sSessionDomain");
		return $this;
	}

	/**
	 * SET COOKIE DOMAIN
	 *
	 * @param string $sCookieDomain
	 * @return $this
	 */
	public function setCookieDomain($sCookieDomain) {
		ini_set('session.cookie_domain', "$sCookieDomain");
		return $this;
	}

	/**
	 * SET COOKIE PATH
	 *
	 * @param string $sPath
	 * @return $this
	 */
	public function setCookiePath($sPath) {
		ini_set('session.cookie_path', "$sPath");
		return $this;
	}

	/**
	 * SET SESSION COOKIE LIFE TIME
	 *
	 * @param int $iSeconds
	 * @return $this
	 */
	public function setCookieLifeTime($iSeconds) {
		ini_set('session.cookie_lifetime', (int) $iSeconds);
		return $this;
	}

	/**
	 * SET SESSION COOKIE SECURE
	 *
	 * @param bool $bState
	 * @return $this
	 */
	public function setCookieSecure($bState) {
		ini_set('session.cookie_secure', (bool) $bState);
		return $this;
	}

	/**
	 * SET SESSION COOKIE HTTP ONLY
	 *
	 * @param bool $bState
	 * @return $this
	 */
	public function setCookieHttpOnly($bState) {
		ini_set('session.cookie_httponly', (bool) $bState);
		return $this;
	}

	/**
	 * SET SESSION PATH
	 *
	 * @param string $sSessionPath
	 * @return $this
	 */
	public function setSessionPath($sSessionPath) {
		ini_set('session.save_path', $sSessionPath);
		return $this;
	}

	/**
	 * SET SESSION NAME
	 *
	 * @param string $sSessionName
	 * @return $this
	 */
	public function setSessionName($sSessionName) {
		ini_set('session.session_name', $sSessionName);
		return $this;
	}

	/**
	 * SET SESSION MAX LIFE TIME
	 *
	 * @param int $iSeconds
	 * @return $this
	 */
	public function setSessionMaxLifeTime($iSeconds) {
		ini_set('session.gc_maxlifetime', (int) $iSeconds);
		return $this;
	}

	/**
	 * SET SESSION DATE
	 *
	 * @param DateTime $oDate
	 * @return $this
	 */
	public function setSessionDate(DateTime $oDate) {
		$this->_oDate = $oDate;
		return $this;
	}

	/**
	 * GETTER SESSION ID
	 *
	 * @return string
	 */
	public function getSessionId() {
		return $this->isActive() ? session_id() : null;
	}

	/**
	 * REGENERATE SESSION ID
	 *
	 * @return $this
	 */
	public function regenerateId() {
		if($this->isActive()) { session_regenerate_id(); }
		return $this;
	}

}
