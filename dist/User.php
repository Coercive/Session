<?php
namespace Coercive\Security\Session;

use Exception;

/**
 * @see \Coercive\Security\Session\Session
 */
class User {

	const
		CONNECTED_PATH = 'connected',
		LOGIN_PATH = 'login',
		ID_PATH = 'id';

	/** @var Session */
	private $_oSession = null;

	/** @var string Session user path */
	private $_sPath = '';

	/**
	 * User constructor.
	 *
	 * @param Session $oSession
	 */
	public function __construct(Session $oSession) {
		$this->_oSession = $oSession;
		$this->_sPath = $oSession->Config()->getUserSessionPath();
	}

	/**
	 * IS CONNECTED STATE
	 *
	 * @return bool
	 * @throws Exception
	 */
	public function isConnected() {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't get user connected state, no session active."); }

		# No datas
		if(empty($_SESSION[$this->_sPath][self::CONNECTED_PATH])) { return false; }

		# Retrieve
		return (bool) $_SESSION[$this->_sPath][self::CONNECTED_PATH];

	}

	/**
	 * SET CONNECTED STATE
	 *
	 * @param bool $bState
	 * @return $this
	 * @throws Exception
	 */
	public function setConnectedState($bState) {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't set user connected state, no session active."); }

		# Set
		$_SESSION[$this->_sPath][self::CONNECTED_PATH] = (bool) $bState;

		# Maintain chainability
		return $this;

	}

	/**
	 * GET USER ID
	 *
	 * @return int
	 * @throws Exception
	 */
	public function getId() {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't get user id, no session active."); }

		# No datas
		if(empty($_SESSION[$this->_sPath][self::ID_PATH])) { return 0; }

		# Retrieve
		return (int) filter_var($_SESSION[$this->_sPath][self::ID_PATH], FILTER_VALIDATE_INT);

	}

	/**
	 * SET USER ID
	 *
	 * @param int $iId
	 * @return $this
	 * @throws Exception
	 */
	public function setId($iId) {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't set user id, no session active."); }

		# Set
		$_SESSION[$this->_sPath][self::ID_PATH] = filter_var($iId, FILTER_VALIDATE_INT) ?: 0;

		# Maintain chainability
		return $this;

	}

	/**
	 * GET USER LOGIN
	 *
	 * @return string
	 * @throws Exception
	 */
	public function getLogin() {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't get user login, no session active."); }

		# No datas
		if(empty($_SESSION[$this->_sPath][self::LOGIN_PATH])) { return ''; }

		# Retrieve
		return (string) strtolower(filter_var($_SESSION[$this->_sPath][self::LOGIN_PATH], FILTER_VALIDATE_EMAIL));

	}

	/**
	 * SET USER LOGIN
	 *
	 * @param string $sEmail
	 * @return $this
	 * @throws Exception
	 */
	public function setLogin($sEmail) {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't set user login, no session active."); }

		# Set
		$_SESSION[$this->_sPath][self::LOGIN_PATH] = strtolower(filter_var($sEmail, FILTER_VALIDATE_EMAIL) ?: '');

		# Maintain chainability
		return $this;

	}

	/**
	 * DELETE USER
	 *
	 * @return $this
	 * @throws Exception
	 */
	public function delete() {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't delete user, no session active."); }

		# Delete
		unset($_SESSION[$this->_sPath][self::LOGIN_PATH], $_SESSION[$this->_sPath][self::ID_PATH], $_SESSION[$this->_sPath][self::CONNECTED_PATH]);

		# Maintain chainability
		return $this;

	}

}