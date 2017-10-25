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
	 * GET USER ID
	 *
	 * @return int
	 * @throws Exception
	 */
	public function getId() {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't get user id, no session active."); }

		# No datas
		if(empty($_SESSION['user']['id'])) { return 0; }

		# Retrieve
		return (int) filter_var($_SESSION['user']['id'], FILTER_VALIDATE_INT);

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
		$_SESSION['user']['id'] = filter_var($iId, FILTER_VALIDATE_INT) ?: 0;

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
	public function setLogin($sEmail) {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't set user login, no session active."); }

		# Set
		$_SESSION['user']['login'] = strtolower(filter_var($sEmail, FILTER_VALIDATE_EMAIL) ?: '');

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
		unset($_SESSION['user']['login'], $_SESSION['user']['id']);

		# Maintain chainability
		return $this;

	}

}