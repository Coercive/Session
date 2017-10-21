<?php
namespace Coercive\Security\Session;

use Exception;

/**
 * @see \Coercive\Security\Session\Session
 */
class User {

	/** @var Session */
	private $_oSession = null;

	/**
	 * User constructor.
	 *
	 * @param Session $oSession
	 */
	public function __construct(Session $oSession) {
		$this->_oSession = $oSession;
	}

	/**
	 * GET USER LOGIN
	 *
	 * @return string
	 * @throws Exception
	 */
	public function get() {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't get user login, no session active."); }

		# No datas
		if(empty($_SESSION['user']['login'])) { return ''; }

		# Retrieve
		return (string) strtolower(filter_var($_SESSION['user']['login'], FILTER_VALIDATE_EMAIL));

	}

	/**
	 * SET USER LOGIN
	 *
	 * @param string $sEmail
	 * @return $this
	 * @throws Exception
	 */
	public function set($sEmail) {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't set user login, no session active."); }

		# Set
		$_SESSION['user']['login'] = strtolower(filter_var($sEmail, FILTER_VALIDATE_EMAIL) ?: '');

		# Maintain chainability
		return $this;

	}

	/**
	 * DELETE USER LOGIN
	 *
	 * @return $this
	 * @throws Exception
	 */
	public function delete() {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't delete user login, no session active."); }

		# Delete
		unset($_SESSION['user']['login']);

		# Maintain chainability
		return $this;

	}

}