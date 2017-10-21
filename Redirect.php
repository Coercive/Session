<?php
namespace Coercive\Security\Session;

use Exception;

/**
 * @see \Coercive\Security\Session\Session
 */
class Redirect {

	/** @var Session */
	private $_oSession = null;

	/**
	 * Redirect constructor.
	 *
	 * @param Session $oSession
	 */
	public function __construct(Session $oSession) {
		$this->_oSession = $oSession;
	}

	/**
	 * GETTER REDIRECT LINK
	 *
	 * @return string
	 * @throws Exception
	 */
	public function get() {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't get redirect link, no session active."); }

		# No datas
		if(empty($_SESSION['redirectLink'])) { return '/'; }

		# Retrieve
		return (string) filter_var($_SESSION['redirectLink'], FILTER_SANITIZE_FULL_SPECIAL_CHARS);

	}

	/**
	 * SETTER REDIRECT LINK
	 *
	 * @param string $sLink
	 * @return $this
	 * @throws Exception
	 */
	public function set($sLink) {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't set redirect link, no session active."); }

		# Set
		$_SESSION['redirectLink'] = (string) filter_var($sLink, FILTER_SANITIZE_FULL_SPECIAL_CHARS);

		# Maintain chainability
		return $this;

	}

	/**
	 * DELETE REDIRECT LINK
	 *
	 * @return $this
	 * @throws Exception
	 */
	public function delete() {

		# Crash
		if(!$this->_oSession->isActive()) { throw new Exception("Can't delete redirect link, no session active."); }

		# Delete
		unset($_SESSION['redirectLink']);

		# Maintain chainability
		return $this;

	}

}