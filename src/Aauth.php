<?php

namespace noraziz\ci4aauth;

/**
 * This is Aauth library for Codeigniter 4.x, maintaned by Nor Aziz <tonoraziz@gmail.com>.
 * 
 * 
 * -- Original Descriptions --
 * Aauth is a User Authorization Library for CodeIgniter 2.x, which aims to make
 * easy some essential jobs such as login, permissions and access operations.
 * Despite ease of use, it has also very advanced features like private messages,
 * groupping, access management, public access etc..
 *
 * @author		Emre Akay <emreakayfb@hotmail.com>
 * @contributor Jacob Tomlinson
 * @contributor Tim Swagger (Renowne, LLC) <tim@renowne.com>
 * @contributor Raphael Jackstadt <info@rejack.de>
 *
 * @copyright 2014-2018 Emre Akay
 *
 * @version 2.5.15
 *
 * @license LGPL
 * @license http://opensource.org/licenses/LGPL-3.0 Lesser GNU Public License
 *
 * The latest version of Aauth can be obtained from:
 * https://github.com/emreakay/CodeIgniter-Aauth
 *
 * @todo separate (on some level) the unvalidated users from the "banned" users
 */

use noraziz\ci4aauth\Config\AauthConfig as AauthCfg;
use noraziz\ci4aauth\Models\AauthModel;

class Aauth
{

	/**
	 * Variable for loading the config array into
	 * @access public
	 * @var array
	 */
	public $config_vars;
	private $session;

	/**
	 * Array to store error messages
	 * @access public
	 * @var array
	 */
	public $errors = array();

	/**
	 * Array to store info messages
	 * @access public
	 * @var array
	 */
	public $infos = array();

	/**
	 * Local temporary storage for current flash errors
	 *
	 * Used to update current flash data list since flash data is only available on the next page refresh
	 * @access public
	 * var array
	 */
	public $flash_errors = array();

	/**
	 * Local temporary storage for current flash infos
	 *
	 * Used to update current flash data list since flash data is only available on the next page refresh
	 * @access public
	 * var array
	 */
	public $flash_infos = array();

	/**
	 * Array to cache permission-ids.
	 * @access private
	 * @var array
	 */
	 private $cache_perm_id;

	/**
	 * Array to cache group-ids.
	 * @access private
	 * @var array
	 */
	 private $cache_group_id;


	/**
	* Constructor
	*
	*/
    public function __construct(?AauthCfg $config = null)
    {
        // If no configuration was supplied then load one
        $this->_config = $config ?? config('AauthConfig');
        
        // Sessions
        $this->session = \Config\Services::session();
        $this->errors  = $this->session->getFlashdata('errors') ?: array();
		$this->infos   = $this->session->getFlashdata('infos') ?: array();
		
		// Initialize Variables
		$this->cache_perm_id  = array();
		$this->cache_group_id = array();
    }
	
	
	
}
